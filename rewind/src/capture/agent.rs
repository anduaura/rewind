use anyhow::Result;

use crate::cli::{FlushArgs, RecordArgs};
use crate::store::snapshot::Snapshot;

pub async fn run(args: RecordArgs) -> Result<()> {
    println!("rewind record");
    println!("  services: {}", args.services.join(", "));
    println!("  output:   {}", args.output.display());
    if args.capture_bodies {
        println!("  bodies:   enabled");
    }

    let snapshot = Snapshot::new(args.services.clone());

    // TODO: load eBPF programs from embedded bytes
    //
    // let mut bpf = Bpf::load(include_bytes_aligned!(
    //     "../../rewind-ebpf/target/bpfel-unknown-none/release/rewind-ebpf"
    // ))?;
    // BpfLogger::init(&mut bpf)?;
    //
    // Attach kprobe:
    //   let probe: &mut KProbe = bpf.program_mut("tcp_sendmsg").unwrap().try_into()?;
    //   probe.load()?;
    //   probe.attach("tcp_sendmsg", 0)?;
    //
    // Attach tracepoint:
    //   let tp: &mut TracePoint = bpf.program_mut("sys_exit").unwrap().try_into()?;
    //   tp.load()?;
    //   tp.attach("syscalls", "sys_exit")?;
    //
    // Drain HTTP_EVENTS perf array (one task per online CPU):
    //   let mut http_array = AsyncPerfEventArray::try_from(
    //       bpf.take_map("HTTP_EVENTS").unwrap()
    //   )?;
    //   for cpu_id in online_cpus()? {
    //       let mut buf = http_array.open(cpu_id, None)?;
    //       tokio::spawn(async move {
    //           let mut buffers = vec![BytesMut::with_capacity(1024); 10];
    //           loop {
    //               let events = buf.read_events(&mut buffers).await.unwrap();
    //               for i in 0..events.read {
    //                   let event = unsafe { ptr::read_unaligned(buffers[i].as_ptr() as *const HttpEvent) };
    //                   // push to shared channel
    //               }
    //           }
    //       });
    //   }

    println!("Recording... press Ctrl+C to flush and exit");

    tokio::signal::ctrl_c().await?;

    println!(
        "\nFlushing {} events to {}",
        snapshot.events.len(),
        args.output.display()
    );
    snapshot.write(&args.output)?;
    println!("Done.");

    Ok(())
}

pub async fn flush(args: FlushArgs) -> Result<()> {
    println!("rewind flush");
    println!("  window: {}", args.window);
    println!("  output: {}", args.output.display());

    // TODO: signal the running agent process to dump the last `window` of its
    // ring buffer to disk. IPC via Unix socket or pidfile + SIGUSR1.
    println!("flush is not yet implemented — start `rewind record` first");

    Ok(())
}
