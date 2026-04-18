use anyhow::Result;

use crate::cli::ReplayArgs;
use crate::store::snapshot::{Event, Snapshot};

pub async fn run(args: ReplayArgs) -> Result<()> {
    let snapshot = Snapshot::read(&args.snapshot)?;

    println!("rewind replay");
    println!("  snapshot: {}", args.snapshot.display());
    println!("  compose:  {}", args.compose.display());
    println!(
        "  events:   {} total",
        snapshot.events.len()
    );

    let http_events: Vec<_> = snapshot
        .events
        .iter()
        .filter_map(|e| if let Event::Http(h) = e { Some(h) } else { None })
        .collect();

    let syscall_events: Vec<_> = snapshot
        .events
        .iter()
        .filter_map(|e| {
            if let Event::Syscall(s) = e {
                Some(s)
            } else {
                None
            }
        })
        .collect();

    println!("  http:     {}", http_events.len());
    println!("  syscalls: {}", syscall_events.len());
    println!();

    // Replay strategy (TODO: implement each step):
    //
    // 1. Parse docker-compose.yml, collect service names and exposed ports.
    //
    // 2. Bring up services:
    //      docker compose -f <compose> up -d
    //
    // 3. Override the system clock to snapshot.recorded_at_ns.
    //    Use libfaketime via LD_PRELOAD injected into compose services, or
    //    set FAKETIME env var before `docker compose up`.
    //
    // 4. Seed random sources.
    //    Build a small LD_PRELOAD shim that intercepts getrandom(2) and
    //    returns values from the SyscallEvent stream in order.
    //
    // 5. Start network.MockServer on a local port.
    //    Load all outbound HttpRecords as canned responses.
    //    Inject HTTP_PROXY=http://localhost:<port> into each service container
    //    so outbound calls are intercepted.
    //
    // 6. Re-execute the triggering request.
    //    The triggering request is the first inbound HttpEvent in the snapshot.
    //    Send it directly to the service's exposed port and capture the response.
    //
    // 7. Compare the response to the recorded response (if present).

    if let Some(trigger) = http_events
        .iter()
        .find(|h| h.direction == "inbound")
    {
        println!(
            "Trigger: {} {}",
            trigger.method, trigger.path
        );
    }

    println!("Replay engine is stubbed — see replay/engine.rs for the implementation plan.");

    Ok(())
}
