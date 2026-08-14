(component
  (type $pending-u32 (future u32))
  (type $byte-stream (stream u8))
  (type $run
    (func async
      (param "pending" $pending-u32)
      (param "chunks" $byte-stream)))
  (import "source" (func $source (type $run)))
  (export "run" (func $source)))
