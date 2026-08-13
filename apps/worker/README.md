# Worker application boundary

The worker will execute an exact admitted run through shared Core and adapters.
It must not receive control-plane database or SCM write credentials. Worker
implementation is deferred to its later plan tasks.
