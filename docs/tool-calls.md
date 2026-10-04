# Authorizing a tool call

A program that lets a language model call functions has the same problem as any
API: some callers may do a thing and some may not. What is different is where
the answer has to live.

**The policy must not be expressible in the language the model speaks.** System
prompts, tool descriptions and instructions are all text, and all arrive in the
same channel as whatever the model just read. A policy evaluated over data is
not persuadable.

Everything on this page but the last section runs as part of the test suite.

```pycon
>>> from pybac import (MatchingPolicy, Policy, PolicyEvaluator,
...                    SecurityContext, SessionContext)

>>> policy = Policy.model_validate({"Statement": [
...     {"Sid": "readTeam", "Effect": "Allow", "Action": ["docs:document:read"],
...      "Condition": {"ForAnyValue:StringEquals": {"target:team": "${req:groups}"}}},
...     {"Sid": "writeOwn", "Effect": "Allow", "Action": ["docs:document:write"],
...      "Condition": {"Expr": {"script": "target.ownerId == req.userId"}}},
...     {"Sid": "bulkNeedsAHuman", "Effect": "RequireApproval",
...      "Action": ["docs:document:write"],
...      "Condition": {"NumericGreaterThan": {"target:wordCount": 1000}}},
... ]})
>>> session = SessionContext(user_id="U1", instance="acme",
...     security_context=SecurityContext(policies=[policy], security_groups=["eng"]))
>>> evaluator = PolicyEvaluator()

>>> DOCUMENTS = {
...     "D1": {"id": "D1", "team": "eng", "ownerId": "U1", "wordCount": 20},
...     "D2": {"id": "D2", "team": "hr", "ownerId": "U9", "wordCount": 20},
...     "D3": {"id": "D3", "team": "eng", "ownerId": "U1", "wordCount": 5000},
... }

```

## Two questions, not one

Which tools to *offer* and whether a call may *proceed* are different questions,
asked at different moments, and answered by different methods. Conflating them
is the usual mistake.

**Which tools exist** is asked before anything has happened. There is no record
yet, so a condition about a record cannot be settled — ask instead whether any
statement could *ever* grant the action:

```pycon
>>> TOOLS = {
...     "read_document":    MatchingPolicy(action="docs:document:read", resource="*"),
...     "write_document":   MatchingPolicy(action="docs:document:write", resource="*"),
...     "publish_document": MatchingPolicy(action="docs:document:publish", resource="*"),
... }

>>> def could_ever(action: MatchingPolicy) -> bool:
...     return bool(evaluator.matching_statements(session, action).all)

>>> sorted(name for name, action in TOOLS.items() if could_ever(action))
['read_document', 'write_document']

```

`publish_document` is never offered, because nothing could ever grant it. Note
what happens if you ask the *other* question here, with no record in hand:

```pycon
>>> evaluator.evaluate(TOOLS["read_document"], session, {})
False

```

Every condition references a record that is not there, so you would advertise
nothing at all.

Filtering the manifest is **not** enforcement. It stops the model attempting the
impossible, which saves retry loops and hallucinated calls. The gate is still
the gate.

**Whether this call may proceed** is asked with the arguments in hand:

```pycon
>>> evaluator.evaluate(TOOLS["read_document"], session, DOCUMENTS["D1"])
True
>>> evaluator.evaluate(TOOLS["read_document"], session, DOCUMENTS["D2"])
False

```

## The model never supplies what the policy judges

The model picks an id. The policy asks about `team` and `ownerId` — which the
model has never seen, and **must never be able to supply**. If a tool took
`team` as a parameter, the model would be feeding its own authorization inputs.

So something has to turn the arguments into the record:

```pycon
>>> def resolve(tool_args: dict) -> dict:
...     """The record a policy should judge, from the id the model chose."""
...     return DOCUMENTS.get(tool_args.get("id"), {})

>>> evaluator.evaluate(TOOLS["read_document"], session, resolve({"id": "D2"}))
False

```

That function is a trust boundary. Everything the policy reads comes from your
data layer; nothing comes from the conversation. Keep it that way, and a model
talked into anything still cannot widen what it may touch.

The same applies to who the principal is, what policies they carry, and the
agent's own attributes. All arrive from outside the conversation, and none of
them should ever be a tool parameter.

## Three outcomes, and telling the model why

A bare `False` makes an agent retry, rephrase, reach for a neighbouring tool, or
report success it did not have. Give it the reason and the loop stops.

```pycon
>>> def authorize(tool: str, tool_args: dict, *, approved: bool = False):
...     decision = evaluator.explain(TOOLS[tool], session, resolve(tool_args))
...     if decision.allowed:
...         return "run"
...     if decision.approval_required and not approved:
...         return f"ask a person: {decision}"
...     if decision.approval_required:
...         return "run"
...     return f"tell the model: {decision}"

>>> authorize("read_document", {"id": "D1"})
'run'
>>> authorize("read_document", {"id": "D2"})
'tell the model: refused: no statement allows it (1 would have, but for a condition)'
>>> authorize("write_document", {"id": "D3"})
"ask a person: awaiting approval, required by statement 'bulkNeedsAHuman'"
>>> authorize("write_document", {"id": "D3"}, approved=True)
'run'

```

Whether approval is needed is a policy decision — `bulkNeedsAHuman` above —
rather than a list of tool names in your code, because the rule is usually
conditional and usually changes. Who may approve, and for how long, is yours.

## A sample: wiring this into pydantic-ai

A complete file, written against **pydantic-ai 2.54**. Illustrative rather than
supported: nothing in the package depends on pydantic-ai, and nothing here is
covered by its tests. It is shown because that framework's two hook points line
up exactly with the two questions above.

```sh
pip install pydantic-ai-slim
```

```python
"""Policy-driven tool authorization for a pydantic-ai agent."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic_ai.exceptions import ApprovalRequired, ModelRetry
from pydantic_ai.toolsets import WrapperToolset
from pydantic_ai.tools import RunContext, ToolDefinition

from pybac import MatchingPolicy, PolicyEvaluator, SessionContext


@dataclass
class Principal:
    """Carried through the run as `deps`: who the agent acts for."""

    session: SessionContext
    supervised: bool = False


@dataclass
class PolicyToolset(WrapperToolset[Principal]):
    """Offers the tools a policy allows, and calls them only when it allows that.

    A tool declares the action it performs in its metadata:

        @toolset.tool_plain(metadata={"action": "docs:document:read"})
        def read_document(id: str) -> dict: ...

    A tool that declares none is refused. Forgetting a keyword argument should
    not quietly leave a tool unguarded, so anything genuinely outside the
    policy -- a clock, a calculator -- is named in `ungoverned` on purpose.
    """

    #: Turns the arguments the model chose into the record a policy judges.
    #: The model picks an id; the policy asks about the owner and the team,
    #: which only your data layer knows -- and which the model must never be
    #: able to supply.
    resolve: Callable[[str, Mapping[str, Any]], Mapping[str, Any]] = (
        lambda name, args: args
    )
    evaluator: PolicyEvaluator = field(default_factory=PolicyEvaluator)
    #: Tools deliberately outside the policy, named one by one.
    ungoverned: frozenset[str] = frozenset()

    @staticmethod
    def _action(tool_def: ToolDefinition) -> str | None:
        return (tool_def.metadata or {}).get("action")

    async def get_tools(self, ctx: RunContext[Principal]) -> dict[str, Any]:
        """Which tools the model is told about.

        There is no record yet, so conditions cannot be settled. Ask instead
        whether any statement could *ever* grant the action.
        """
        offered = {}
        for name, tool in (await super().get_tools(ctx)).items():
            action = self._action(tool.tool_def)
            if action is None:
                if name not in self.ungoverned:
                    raise RuntimeError(
                        f"tool {name!r} declares no action: add "
                        f'metadata={{"action": ...}}, or name it in ungoverned'
                    )
                offered[name] = tool
            elif self.evaluator.matching_statements(
                ctx.deps.session, MatchingPolicy(action=action, resource="*")
            ).all:
                offered[name] = tool
        return offered

    async def call_tool(
        self,
        name: str,
        tool_args: dict[str, Any],
        ctx: RunContext[Principal],
        tool: Any,
    ) -> Any:
        """Whether this call proceeds, weighed against the record it names."""
        action = self._action(tool.tool_def)
        if action is None:
            if name not in self.ungoverned:
                raise RuntimeError(f"tool {name!r} declares no action")
            return await super().call_tool(name, tool_args, ctx, tool)

        decision = self.evaluator.explain(
            MatchingPolicy(action=action, resource="*"),
            ctx.deps.session,
            self.resolve(name, tool_args),
            {"agent": {"supervised": ctx.deps.supervised}},
        )
        if decision.approval_required:
            # `allowed` stays False until a person says yes, so an approved
            # call must be let through here rather than by the check below.
            if not ctx.tool_call_approved:
                raise ApprovalRequired
        elif not decision.allowed:
            raise ModelRetry(str(decision))  # the model is told why
        return await super().call_tool(name, tool_args, ctx, tool)
```

A tool declares the action it performs, and the resolver turns the arguments
the model chose into the record a policy can judge:

```python
tools = FunctionToolset[Principal]()


@tools.tool_plain(metadata={"action": "docs:document:read"})
def read_document(id: str) -> dict:
    """Read a document."""
    return DOCUMENTS[id]


guarded = PolicyToolset(
    wrapped=tools,
    resolve=lambda name, args: DOCUMENTS.get(args.get("id"), {}),
)
agent = Agent(model, deps_type=Principal, toolsets=[guarded])
```

Against the policy at the top of this page, that gives:

```text
offered to the model: ['read_document', 'write_document']

read D1 (own team)     ran, returned {'id': 'D1', 'team': 'eng', ...}
read D2 (HR)           ModelRetry(refused: no statement allows it (1 would have, but for a condition))
write D3 (5000 words)  ApprovalRequired -- pause and ask a person
...after approval      ran, returned 'written'

forgot the metadata: tool 'whoami' declares no action: add
                     metadata={"action": ...}, or name it in ungoverned
```

`publish_document` never appears, because no statement could ever grant it.

### Before you ship this

Five things that will bite, in the order they are likely to.

**Every tool must declare an action.** The sample raises rather than passing an
undeclared tool through, because a forgotten keyword argument should not
silently remove a guard. Tools genuinely outside the policy -- a clock, a
calculator -- are named in `ungoverned` deliberately, one at a time.

**The resolver receives model-controlled input.** `tool_args` is whatever the
model decided to send. Treat it as you would a query string: never interpolate
it into SQL, a path, or a shell command. A resolver that is injectable hands an
attacker the ability to choose which record gets authorized.

**Wrap every toolset.** `PolicyToolset` governs what it wraps and nothing else.
A tool passed to the agent another way, or living in a second toolset, is
reachable and ungoverned -- and nothing will tell you.

**Nothing the model emits may reach `deps`.** The principal, their policies and
the agent's own attributes come from your runtime, never from the conversation
and never from a tool argument. If the model can influence `deps`, it is
choosing its own permissions.

**An approval belongs to those arguments.** `tool_call_approved` applies to the
call a person actually saw. Do not cache an approval and reuse it for a later
call with different arguments.

### Three things to adapt

**The resolver is the part you write.** Here it reads a dict; in your code it
reads your database. Make it `async` if it does I/O and `await` it in
`call_tool` -- the sample keeps it synchronous only to stay short.

**An approval is a pause, not a failure.** `ApprovalRequired` suspends the run
for a person; the framework resumes it with `tool_call_approved` set. Note the
shape of that branch: `decision.allowed` stays `False` for an approved call, so
the approval has to be let through on its own path. Checking `not
decision.allowed` first would refuse the very call a person had just approved.
I wrote that bug while preparing this page.

**Filtering the manifest is not enforcement.** `get_tools` only stops the model
attempting the impossible. `call_tool` is the gate. You need both.

### The same seams elsewhere

Any tool-calling loop has three: a manifest, a call site, and a way to send a
message back to the model. A framework only decides what they are called.

| what you need | pydantic-ai |
|---|---|
| declare the action a tool performs | `ToolDefinition.metadata` |
| reach the principal during a run | `RunContext.deps` |
| advertise a tool | `AbstractToolset.get_tools` |
| gate a call | `AbstractToolset.call_tool` |
| tell the model why | `ModelRetry` |
| pause for a person | `ApprovalRequired` |

## See also

- [usage.md](usage.md) — the guide.
- [behaviour.md](behaviour.md) — the sharp edges.
