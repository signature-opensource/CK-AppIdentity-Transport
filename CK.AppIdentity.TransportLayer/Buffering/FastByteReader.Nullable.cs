using CK.Core;
using System;

namespace CK.AppIdentity.TransportLayer
{
    public ref partial struct FastByteReader
    {
        /// <summary>
        /// Reads a nullable boolean value.
        /// </summary>
        /// <returns>The read value.</returns>
        public bool? ReadNullableBool()
        {
            return ReadByte() switch
            {
                1 => true,
                2 => false,
                3 => null,
                _ => Throw.InvalidDataException<bool>()
            };
        }

        public short? ReadNullableInt16() => ReadByte() == 1 ? ReadInt16() : null;

        public ushort? ReadNullableUInt16() => ReadByte() == 1 ? ReadUInt16() : null;

        public int? ReadNullableInt32() => ReadByte() == 1 ? ReadInt32() : null;

        public uint? ReadNullableUInt32() => ReadByte() == 1 ? ReadUInt32() : null;

        public long? ReadNullableInt64() => ReadByte() == 1 ? ReadInt64() : null;

        public ulong? ReadNullableUInt64() => ReadByte() == 1 ? ReadUInt64() : null;

        public float? ReadNullableSingle() => ReadByte() == 1 ? ReadSingle() : null;

        public double? ReadNullableDouble() => ReadByte() == 1 ? ReadDouble() : null;

        public DateTime? ReadNullableDateTime() => ReadByte() == 1 ? ReadDateTime() : null;

        public TimeSpan? ReadNullableTimeSpan() => ReadByte() == 1 ? ReadTimeSpan() : null;

        public char? ReadNullableChar()
        {
            var v = ReadSmallUInt32();
            return v == 0 ? null : (char)(v - 1);
        }

        public string? ReadNullableString() => ReadByte() == 1 ? ReadString() : null;

    }

}

