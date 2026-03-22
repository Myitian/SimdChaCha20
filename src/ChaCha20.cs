using System.Buffers;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

#pragma warning disable CA1034
namespace SimdChaCha20;

public sealed class ChaCha20
{
    [InlineArray(Length)]
    public struct Key : IEquatable<Key>, IEqualityOperators<Key, Key, bool>
    {
        public const int Length = 8;
        private uint _;

        public Key(ReadOnlySpan<uint> key)
        {
            ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, Length);
            key.CopyTo(this);
        }
        public Key(ReadOnlySpan<byte> key)
        {
            ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, Length * sizeof(uint));
            MemoryMarshal.Cast<byte, uint>(key).CopyTo(this);
            if (!BitConverter.IsLittleEndian)
                BinaryPrimitives.ReverseEndianness(this, this);
        }

        public readonly bool Equals(Key other)
            => ((ReadOnlySpan<uint>)this).SequenceEqual(other);
        public override readonly bool Equals(object? obj)
            => obj is Key key && Equals(key);
        public override readonly int GetHashCode()
            => HashCode.Combine(this[0], this[1], this[2], this[3], this[4], this[5], this[6], this[7]);
        public static bool operator ==(Key left, Key right)
            => left.Equals(right);
        public static bool operator !=(Key left, Key right)
            => !left.Equals(right);
    }
    [InlineArray(Length)]
    public struct Nonce : IEquatable<Nonce>, IEqualityOperators<Nonce, Nonce, bool>
    {
        public const int Length = 3;
        private uint _;

        public Nonce(ReadOnlySpan<uint> key)
        {
            ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, Length);
            key.CopyTo(this);
        }
        public Nonce(ReadOnlySpan<byte> nonce)
        {
            ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, Length * sizeof(uint));
            MemoryMarshal.Cast<byte, uint>(nonce).CopyTo(this);
            if (!BitConverter.IsLittleEndian)
                BinaryPrimitives.ReverseEndianness(this, this);
        }

        public readonly bool Equals(Nonce other)
            => ((ReadOnlySpan<uint>)this).SequenceEqual(other);
        public override readonly bool Equals(object? obj)
            => obj is Nonce nonce && Equals(nonce);
        public override readonly int GetHashCode()
            => HashCode.Combine(this[0], this[1], this[2]);
        public static bool operator ==(Nonce left, Nonce right)
            => left.Equals(right);
        public static bool operator !=(Nonce left, Nonce right)
            => !left.Equals(right);
    }
    [InlineArray(16)]
    private struct State
    {
        private uint _;
    }

    private State state;
    private static ReadOnlySpan<uint> Sigma => [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]; // "expand 32-byte k"
    public uint Counter
    {
        get => state[12];
        set => state[12] = value;
    }
    public ChaCha20(Key key, Nonce nonce, uint counter = 0)
    {
        Sigma.CopyTo(state);
        ((ReadOnlySpan<uint>)key).CopyTo(state[4..]);
        ((ReadOnlySpan<uint>)nonce).CopyTo(state[13..]);
        Counter = counter;
    }
    public ChaCha20(ReadOnlySpan<uint> key, ReadOnlySpan<uint> nonce, uint counter = 0)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, 8);
        ArgumentOutOfRangeException.ThrowIfNotEqual(nonce.Length, 3);
        Sigma.CopyTo(state);
        key.CopyTo(state[4..]);
        nonce.CopyTo(state[13..]);
        Counter = counter;
    }
    public ChaCha20(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, uint counter)
        : this(new Key(key), new Nonce(nonce), counter)
    {
    }
    public void Process(Stream input, Stream output, int bufferSize = 8192)
    {
        if (bufferSize == 0)
            bufferSize = 8192;
        ArgumentOutOfRangeException.ThrowIfLessThan(bufferSize, 64);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            Span<byte> span = buffer;
            int remaining = 0;
            while (true)
            {
                int read = input.Read(span[remaining..]);
                remaining += read;
                if (read == 0)
                {
                    if (remaining > 0)
                    {
                        Span<byte> slice = span[..remaining];
                        Process(slice, slice);
                        output.Write(slice);
                    }
                    break;
                }
                else
                {
                    int newRemaining = remaining % 64;
                    int processing = remaining - newRemaining;
                    if (processing > 0)
                    {
                        Span<byte> slice = span[..processing];
                        Process(slice, slice);
                        output.Write(slice);
                    }
                    if (newRemaining > 0)
                        span.Slice(processing, newRemaining).CopyTo(span);
                    remaining = newRemaining;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
    public async Task ProcessAsync(Stream input, Stream output, int bufferSize = 8192, CancellationToken cancellationToken = default)
    {
        if (bufferSize == 0)
            bufferSize = 8192;
        ArgumentOutOfRangeException.ThrowIfLessThan(bufferSize, 64);
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(output);
        byte[] buffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        try
        {
            Memory<byte> span = buffer;
            int remaining = 0;
            while (true)
            {
                int read = await input.ReadAsync(span[remaining..], cancellationToken).ConfigureAwait(false);
                remaining += read;
                if (read == 0)
                {
                    if (remaining > 0)
                    {
                        Memory<byte> slice = span[..remaining];
                        Process(slice.Span, slice.Span);
                        await output.WriteAsync(slice, cancellationToken).ConfigureAwait(false);
                    }
                    break;
                }
                else
                {
                    int newRemaining = remaining % 64;
                    int processing = remaining - newRemaining;
                    if (processing > 0)
                    {
                        Memory<byte> slice = span[..processing];
                        Process(slice.Span, slice.Span);
                        await output.WriteAsync(slice, cancellationToken).ConfigureAwait(false);
                    }
                    if (newRemaining > 0)
                        span.Slice(processing, newRemaining).CopyTo(span);
                    remaining = newRemaining;
                }
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
    public void Process(ReadOnlySpan<byte> input, Span<byte> output)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(output.Length, input.Length);
        ProcessUnsafe(in MemoryMarshal.GetReference(input), ref MemoryMarshal.GetReference(output), (nuint)input.Length);
    }
    public void ProcessUnsafe(ref readonly byte input, ref byte output, nuint count)
    {
        State workingBuffer = default;
        ref byte buffer = ref Unsafe.As<State, byte>(ref workingBuffer);

        (nuint fullLoops, nuint tailBytes) = Math.DivRem(count, (nuint)Unsafe.SizeOf<State>());

        for (nuint loop = 0; loop < fullLoops; loop++)
        {
            UpdateState(ref state, ref workingBuffer);
            if (Vector512.IsHardwareAccelerated)
            {
                (Vector512.LoadUnsafe(in input) ^ Vector512.LoadUnsafe(ref buffer)).StoreUnsafe(ref output);
            }
            else if (Vector256.IsHardwareAccelerated)
            {
                (Vector256.LoadUnsafe(in input) ^ Vector256.LoadUnsafe(ref buffer)).StoreUnsafe(ref output);
                (Vector256.LoadUnsafe(in input, 32) ^ Vector256.LoadUnsafe(ref buffer, 32)).StoreUnsafe(ref output, 32);
            }
            else if (Vector128.IsHardwareAccelerated)
            {
                (Vector128.LoadUnsafe(in input) ^ Vector128.LoadUnsafe(ref buffer)).StoreUnsafe(ref output);
                (Vector128.LoadUnsafe(in input, 16) ^ Vector128.LoadUnsafe(ref buffer, 16)).StoreUnsafe(ref output, 16);
                (Vector128.LoadUnsafe(in input, 32) ^ Vector128.LoadUnsafe(ref buffer, 32)).StoreUnsafe(ref output, 32);
                (Vector128.LoadUnsafe(in input, 48) ^ Vector128.LoadUnsafe(ref buffer, 48)).StoreUnsafe(ref output, 48);
            }
            else
            {
                Unsafe.WriteUnaligned(ref output, Unsafe.ReadUnaligned<ulong>(in input) ^ Unsafe.ReadUnaligned<ulong>(in buffer));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 8), Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref Unsafe.AsRef(in input), 8)) ^ Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref buffer, 8)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 16), Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref Unsafe.AsRef(in input), 16)) ^ Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref buffer, 16)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 24), Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref Unsafe.AsRef(in input), 24)) ^ Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref buffer, 24)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 32), Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref Unsafe.AsRef(in input), 32)) ^ Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref buffer, 32)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 40), Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref Unsafe.AsRef(in input), 40)) ^ Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref buffer, 40)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 48), Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref Unsafe.AsRef(in input), 48)) ^ Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref buffer, 48)));
                Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 56), Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref Unsafe.AsRef(in input), 56)) ^ Unsafe.ReadUnaligned<ulong>(in Unsafe.Add(ref buffer, 56)));
            }
            input = ref Unsafe.Add(ref Unsafe.AsRef(in input), 64);
            output = ref Unsafe.Add(ref output, 64);
        }

        if (tailBytes > 0)
        {
            UpdateState(ref state, ref workingBuffer);
            while (tailBytes >= 8)
            {
                Unsafe.WriteUnaligned(ref output, Unsafe.ReadUnaligned<ulong>(in input) ^ Unsafe.ReadUnaligned<ulong>(in buffer));
                input = ref Unsafe.Add(ref Unsafe.AsRef(in input), 8);
                output = ref Unsafe.Add(ref output, 8);
                buffer = ref Unsafe.Add(ref buffer, 8);
                tailBytes -= 8;
            }
            for (nuint i = 0; i < tailBytes; i++)
            {
                Unsafe.Add(ref output, i) = (byte)(Unsafe.Add(ref Unsafe.AsRef(in input), i) ^ Unsafe.Add(ref buffer, i));
            }
        }
    }
    private static void UpdateState(ref State state, ref State workingBuffer)
    {
        workingBuffer = state;
        ref uint stateU = ref MemoryMarshal.GetReference<uint>(state);
        ref uint workingBufferU = ref MemoryMarshal.GetReference<uint>(workingBuffer);
        for (int i = 0; i < 10; i++)
        {
            QuarterRound(ref workingBufferU, 0, 4, 8, 12);
            QuarterRound(ref workingBufferU, 1, 5, 9, 13);
            QuarterRound(ref workingBufferU, 2, 6, 10, 14);
            QuarterRound(ref workingBufferU, 3, 7, 11, 15);

            QuarterRound(ref workingBufferU, 0, 5, 10, 15);
            QuarterRound(ref workingBufferU, 1, 6, 11, 12);
            QuarterRound(ref workingBufferU, 2, 7, 8, 13);
            QuarterRound(ref workingBufferU, 3, 4, 9, 14);
        }
        if (Vector512.IsHardwareAccelerated)
        {
            (Vector512.LoadUnsafe(ref workingBufferU) + Vector512.LoadUnsafe(ref stateU)).StoreUnsafe(ref workingBufferU);
        }
        else if (Vector256.IsHardwareAccelerated)
        {
            (Vector256.LoadUnsafe(ref workingBufferU) + Vector256.LoadUnsafe(ref stateU)).StoreUnsafe(ref workingBufferU);
            (Vector256.LoadUnsafe(ref workingBufferU, 8) + Vector256.LoadUnsafe(ref stateU, 8)).StoreUnsafe(ref workingBufferU, 8);
        }
        else if (Vector128.IsHardwareAccelerated)
        {
            (Vector128.LoadUnsafe(ref workingBufferU) + Vector128.LoadUnsafe(ref stateU)).StoreUnsafe(ref workingBufferU);
            (Vector128.LoadUnsafe(ref workingBufferU, 4) + Vector128.LoadUnsafe(ref stateU, 8)).StoreUnsafe(ref workingBufferU, 4);
            (Vector128.LoadUnsafe(ref workingBufferU, 8) + Vector128.LoadUnsafe(ref stateU, 8)).StoreUnsafe(ref workingBufferU, 8);
            (Vector128.LoadUnsafe(ref workingBufferU, 12) + Vector128.LoadUnsafe(ref stateU, 8)).StoreUnsafe(ref workingBufferU, 12);
        }
        else
        {
            workingBuffer[0x0] += state[0x0];
            workingBuffer[0x1] += state[0x1];
            workingBuffer[0x2] += state[0x2];
            workingBuffer[0x3] += state[0x3];
            workingBuffer[0x4] += state[0x4];
            workingBuffer[0x5] += state[0x5];
            workingBuffer[0x6] += state[0x6];
            workingBuffer[0x7] += state[0x7];
            workingBuffer[0x8] += state[0x8];
            workingBuffer[0x9] += state[0x9];
            workingBuffer[0xA] += state[0xA];
            workingBuffer[0xB] += state[0xB];
            workingBuffer[0xC] += state[0xC];
            workingBuffer[0xD] += state[0xD];
            workingBuffer[0xE] += state[0xE];
            workingBuffer[0xF] += state[0xF];
        }
        if (!BitConverter.IsLittleEndian)
            BinaryPrimitives.ReverseEndianness(workingBuffer, workingBuffer);
        if (++state[12] == 0)
            throw new OverflowException("Counter overflow");
    }
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void QuarterRound(ref uint x,
        [ConstantExpected(Min = 0, Max = 15)] int a,
        [ConstantExpected(Min = 0, Max = 15)] int b,
        [ConstantExpected(Min = 0, Max = 15)] int c,
        [ConstantExpected(Min = 0, Max = 15)] int d)
    {
        uint ta = Unsafe.Add(ref x, a);
        uint tb = Unsafe.Add(ref x, b);
        uint tc = Unsafe.Add(ref x, c);
        uint td = Unsafe.Add(ref x, d);
        ta += tb;
        td = BitOperations.RotateLeft(td ^ ta, 16);
        tc += td;
        tb = BitOperations.RotateLeft(tb ^ tc, 12);
        ta += tb;
        td = BitOperations.RotateLeft(td ^ ta, 8);
        tc += td;
        tb = BitOperations.RotateLeft(tb ^ tc, 7);
        Unsafe.Add(ref x, a) = ta;
        Unsafe.Add(ref x, b) = tb;
        Unsafe.Add(ref x, c) = tc;
        Unsafe.Add(ref x, d) = td;
    }
}