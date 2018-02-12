using System;
using System.IO;
using System.Text;
using PacketDotNet.Utils.Conversion;

namespace PacketDotNet.Utils.IO
{
    /// <summary>
    ///     Equivalent of System.IO.BinaryWriter, but with either endianness, depending on
    ///     the EndianBitConverter it is constructed with.
    /// </summary>
    public class EndianBinaryWriter : IDisposable
    {
        #region IDisposable Members

        /// <summary>
        ///     Disposes of the underlying stream.
        /// </summary>
        public void Dispose()
        {
            if (this.disposed) return;

            this.Flush();
            this.disposed = true;
            ((IDisposable) this.BaseStream).Dispose();
        }

        #endregion

        #region Fields not directly related to properties

        /// <summary>
        ///     Whether or not this writer has been disposed yet.
        /// </summary>
        private Boolean disposed;

        /// <summary>
        ///     Buffer used for temporary storage during conversion from primitives
        /// </summary>
        private readonly Byte[] buffer = new Byte[16];

        /// <summary>
        ///     Buffer used for Write(char)
        /// </summary>
        private readonly Char[] charBuffer = new Char[1];

        #endregion

        #region Constructors

        /// <summary>
        ///     Constructs a new binary writer with the given bit converter, writing
        ///     to the given stream, using UTF-8 encoding.
        /// </summary>
        /// <param name="bitConverter">Converter to use when writing data</param>
        /// <param name="stream">Stream to write data to</param>
        public EndianBinaryWriter(EndianBitConverter bitConverter,
            Stream stream) : this(bitConverter, stream, Encoding.UTF8)
        {
        }

        /// <summary>
        ///     Constructs a new binary writer with the given bit converter, writing
        ///     to the given stream, using the given encoding.
        /// </summary>
        /// <param name="bitConverter">Converter to use when writing data</param>
        /// <param name="stream">Stream to write data to</param>
        /// <param name="encoding">Encoding to use when writing character data</param>
        public EndianBinaryWriter(EndianBitConverter bitConverter, Stream stream, Encoding encoding)
        {
            if (stream == null)
            {
                throw new ArgumentNullException("stream");
            }

            if (!stream.CanWrite)
            {
                throw new ArgumentException("Stream isn't writable", "stream");
            }

            this.BaseStream = stream;
            this.BitConverter = bitConverter ?? throw new ArgumentNullException("bitConverter");
            this.Encoding = encoding ?? throw new ArgumentNullException("encoding");
        }

        #endregion

        #region Properties

        /// <summary>
        ///     The bit converter used to write values to the stream
        /// </summary>
        public EndianBitConverter BitConverter { get; }

        /// <summary>
        ///     The encoding used to write strings
        /// </summary>
        public Encoding Encoding { get; }

        /// <summary>
        ///     Gets the underlying stream of the EndianBinaryWriter.
        /// </summary>
        public Stream BaseStream { get; }

        #endregion

        #region Public methods

        /// <summary>
        ///     Closes the writer, including the underlying stream.
        /// </summary>
        public void Close()
        {
            this.Dispose();
        }

        /// <summary>
        ///     Flushes the underlying stream.
        /// </summary>
        public void Flush()
        {
            this.CheckDisposed();
            this.BaseStream.Flush();
        }

        /// <summary>
        ///     Seeks within the stream.
        /// </summary>
        /// <param name="offset">Offset to seek to.</param>
        /// <param name="origin">Origin of seek operation.</param>
        public void Seek(Int32 offset, SeekOrigin origin)
        {
            this.CheckDisposed();
            this.BaseStream.Seek(offset, origin);
        }

        /// <summary>
        ///     Writes a boolean value to the stream. 1 byte is written.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(Boolean value)
        {
            this.BitConverter.CopyBytes(value, this.buffer, 0);
            this.WriteInternal(this.buffer, 1);
        }

        /// <summary>
        ///     Writes a 16-bit signed integer to the stream, using the bit converter
        ///     for this writer. 2 bytes are written.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(Int16 value)
        {
            this.BitConverter.CopyBytes(value, this.buffer, 0);
            this.WriteInternal(this.buffer, 2);
        }

        /// <summary>
        ///     Writes a 32-bit signed integer to the stream, using the bit converter
        ///     for this writer. 4 bytes are written.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(Int32 value)
        {
            this.BitConverter.CopyBytes(value, this.buffer, 0);
            this.WriteInternal(this.buffer, 4);
        }

        /// <summary>
        ///     Writes a 64-bit signed integer to the stream, using the bit converter
        ///     for this writer. 8 bytes are written.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(Int64 value)
        {
            this.BitConverter.CopyBytes(value, this.buffer, 0);
            this.WriteInternal(this.buffer, 8);
        }

        /// <summary>
        ///     Writes a 16-bit unsigned integer to the stream, using the bit converter
        ///     for this writer. 2 bytes are written.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(UInt16 value)
        {
            this.BitConverter.CopyBytes(value, this.buffer, 0);
            this.WriteInternal(this.buffer, 2);
        }

        /// <summary>
        ///     Writes a 32-bit unsigned integer to the stream, using the bit converter
        ///     for this writer. 4 bytes are written.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(UInt32 value)
        {
            this.BitConverter.CopyBytes(value, this.buffer, 0);
            this.WriteInternal(this.buffer, 4);
        }

        /// <summary>
        ///     Writes a 64-bit unsigned integer to the stream, using the bit converter
        ///     for this writer. 8 bytes are written.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(UInt64 value)
        {
            this.BitConverter.CopyBytes(value, this.buffer, 0);
            this.WriteInternal(this.buffer, 8);
        }

        /// <summary>
        ///     Writes a single-precision floating-point value to the stream, using the bit converter
        ///     for this writer. 4 bytes are written.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(Single value)
        {
            this.BitConverter.CopyBytes(value, this.buffer, 0);
            this.WriteInternal(this.buffer, 4);
        }

        /// <summary>
        ///     Writes a double-precision floating-point value to the stream, using the bit converter
        ///     for this writer. 8 bytes are written.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(Double value)
        {
            this.BitConverter.CopyBytes(value, this.buffer, 0);
            this.WriteInternal(this.buffer, 8);
        }

        /// <summary>
        ///     Writes a decimal value to the stream, using the bit converter for this writer.
        ///     16 bytes are written.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(Decimal value)
        {
            this.BitConverter.CopyBytes(value, this.buffer, 0);
            this.WriteInternal(this.buffer, 16);
        }

        /// <summary>
        ///     Writes a signed byte to the stream.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(Byte value)
        {
            this.buffer[0] = value;
            this.WriteInternal(this.buffer, 1);
        }

        /// <summary>
        ///     Writes an unsigned byte to the stream.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(SByte value)
        {
            this.buffer[0] = unchecked((Byte) value);
            this.WriteInternal(this.buffer, 1);
        }

        /// <summary>
        ///     Writes an array of bytes to the stream.
        /// </summary>
        /// <param name="value">The values to write</param>
        public void Write(Byte[] value)
        {
            if (value == null)
            {
                throw (new ArgumentNullException("value"));
            }

            this.WriteInternal(value, value.Length);
        }

        /// <summary>
        ///     Writes a portion of an array of bytes to the stream.
        /// </summary>
        /// <param name="value">An array containing the bytes to write</param>
        /// <param name="offset">The index of the first byte to write within the array</param>
        /// <param name="count">The number of bytes to write</param>
        public void Write(Byte[] value, Int32 offset, Int32 count)
        {
            this.CheckDisposed();
            this.BaseStream.Write(value, offset, count);
        }

        /// <summary>
        ///     Writes a single character to the stream, using the encoding for this writer.
        /// </summary>
        /// <param name="value">The value to write</param>
        public void Write(Char value)
        {
            this.charBuffer[0] = value;
            this.Write(this.charBuffer);
        }

        /// <summary>
        ///     Writes an array of characters to the stream, using the encoding for this writer.
        /// </summary>
        /// <param name="value">An array containing the characters to write</param>
        public void Write(Char[] value)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }

            this.CheckDisposed();
            Byte[] data = this.Encoding.GetBytes(value, 0, value.Length);
            this.WriteInternal(data, data.Length);
        }

        /// <summary>
        ///     Writes a string to the stream, using the encoding for this writer.
        /// </summary>
        /// <param name="value">The value to write. Must not be null.</param>
        /// <exception cref="ArgumentNullException">value is null</exception>
        public void Write(String value)
        {
            if (value == null)
            {
                throw new ArgumentNullException("value");
            }

            this.CheckDisposed();
            Byte[] data = this.Encoding.GetBytes(value);
            this.Write7BitEncodedInt(data.Length);
            this.WriteInternal(data, data.Length);
        }

        /// <summary>
        ///     Writes a 7-bit encoded integer from the stream. This is stored with the least significant
        ///     information first, with 7 bits of information per byte of value, and the top
        ///     bit as a continuation flag.
        /// </summary>
        /// <param name="value">The 7-bit encoded integer to write to the stream</param>
        public void Write7BitEncodedInt(Int32 value)
        {
            this.CheckDisposed();
            if (value < 0)
            {
                throw new ArgumentOutOfRangeException("value", "Value must be greater than or equal to 0.");
            }

            Int32 index = 0;
            while (value >= 128)
            {
                this.buffer[index++] = (Byte) ((value & 0x7f) | 0x80);
                value = value >> 7;
                index++;
            }

            this.buffer[index++] = (Byte) value;
            this.BaseStream.Write(this.buffer, 0, index);
        }

        #endregion

        #region Private methods

        /// <summary>
        ///     Checks whether or not the writer has been disposed, throwing an exception if so.
        /// </summary>
        private void CheckDisposed()
        {
            if (this.disposed)
            {
                throw new ObjectDisposedException("EndianBinaryWriter");
            }
        }

        /// <summary>
        ///     Writes the specified number of bytes from the start of the given byte array,
        ///     after checking whether or not the writer has been disposed.
        /// </summary>
        /// <param name="bytes">The array of bytes to write from</param>
        /// <param name="length">The number of bytes to write</param>
        private void WriteInternal(Byte[] bytes, Int32 length)
        {
            this.CheckDisposed();
            this.BaseStream.Write(bytes, 0, length);
        }

        #endregion
    }
}