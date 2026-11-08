# Low level "byte stream" and memory management

## MutableSequence
This is disposable `IBufferWriter<T>` (where T is constrained to struct) that manages its buffers
and memory segments.

It supports adding pre-allocated segments in the form of array of `T` or of `IMemoryOwner<T>`:
```csharp
/// <summary>
/// Adds an array of <typeparamref name="T"/>.
/// The content of the array should not be mutated once added.
/// Note that if this is an empty array, nothing is done.
/// </summary>
/// <param name="data">A non empty array.</param>
public void AddSegment( T[] data );

/// <summary>
/// Adds a non empty data managed by another memory pool. The ownership is transfered to
/// this sequence: the memory will be disposed by this <see cref="Clear()"/>.
/// <para>
/// If the <see cref="Memory{T}.Length"/> is 0 (data is empty) this throws an <see cref="ArgumentException"/>
/// because we don't allow an empty segment and there is an ambiguity on whether Dispose() should
/// be called or not on an empty buffer.
/// </para>
/// <para>
/// The memory should not be mutated once added.
/// </para>
/// </summary>
/// <param name="data">The non empty memory to add.</param>
public void AddSegment( IMemoryOwner<T> data );
```
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

## Length-prefixed blocks

A structure that must stay extensible is written in a block: `FastByteWriter.BeginBlock()` reserves its length (4 bytes,
little endian) and returns a `FastByteBlock`, `FastByteWriter.EndBlock( block )` writes the length of what has been
written since. Blocks can be nested.

`FastByteReader.ReadBlock()` returns a reader on the content of the block and moves the reader after it, whatever is
read from the block's reader:
- a reader reads the fields it knows and ignores the ones that a newer writer added at the end of the block;
- a newer reader of an older block finds the block's end (`FastByteReader.IsEnd`) where its newer fields would be: they
  keep their default.

`FastByteReader.Skip( count )` skips bytes, across the segments.
