# Low level "byte stream" and memory management

## MutableSequence
This is disposable `IBufferWriter<T>` (where T is constrained to struct) that manages its buffers
and memory segments.

## FastByteReader and FastByteWriter

The FastByteReader/Writer are heavily inspired by the Orleans reader/writer.

The FastByteWriter offers Write methods for basic types (byte, DateTime, Guid, string, etc.) and is a ref struct
on a `IBufferWriter<byte>`.
And the question is: "Why not do you need another layer upon it?".
This is a good question: those helpers could have been extension methods of `IBufferWriter<byte>`, however this would be
less optimal than the FastByteWriter helper in terms of memory management. Basically, the FastByteWriter handles
the current available span and exploits it efficiently as much as it can. Extension methods cannot do this: they must
systematically call `IBufferWriter<byte>.GetSpan()` or `IBufferWriter<byte>.GetMemory()` initially (and this call
is a `callvirt`).

The `FastByteWriter.Commit()` method must be called before loosing the writer so that `IBufferWriter<bute>.Advance(int)` is called
and whatever has been written to the current span is transfered to the `IBufferWriter<byte>`.

