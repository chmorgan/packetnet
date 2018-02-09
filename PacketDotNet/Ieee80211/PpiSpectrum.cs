using System.IO;

namespace PacketDotNet.Ieee80211
{
    /// <summary>
    /// The PPI Spectrum field is intended to be compatible with the sweep records
    /// returned by the Wi-Spy spectrum analyzer.
    /// </summary>
    public class PpiSpectrum : PpiField
    {
        #region Properties

        /// <summary>Type of the field</summary>
        public override PpiFieldType FieldType
        {
            get { return PpiFieldType.PpiSpectrum;}
        }
            
        /// <summary>
        /// Gets the length of the field data.
        /// </summary>
        /// <value>
        /// The length.
        /// </value>
        public override int Length { get { return 20 + this.SamplesData.Length; } }
        /// <summary>
        /// Gets or sets the starting frequency in kHz.
        /// </summary>
        /// <value>
        /// The starting frequency.
        /// </value>
        public uint StartingFrequency { get; set; }
        /// <summary>
        /// Gets or sets the resolution of each sample in Hz.
        /// </summary>
        /// <value>
        /// The resolution in Hz.
        /// </value>
        public uint Resolution { get; set; }
        /// <summary>
        /// Gets or sets the amplitude offset (in 0.001 dBm)
        /// </summary>
        /// <value>
        /// The amplitude offset.
        /// </value>
        public uint AmplitudeOffset { get; set; }
        /// <summary>
        /// Gets or sets the amplitude resolution (in .001 dBm)
        /// </summary>
        /// <value>
        /// The amplitude resolution.
        /// </value>
        public uint AmplitudeResolution { get; set; }
        /// <summary>
        /// Gets or sets the maximum raw RSSI value reported by the device.
        /// </summary>
        /// <value>
        /// The maximum rssi.
        /// </value>
        public ushort MaximumRssi { get; set; }
        /// <summary>
        /// Gets or sets the data samples.
        /// </summary>
        /// <value>
        /// The data samples.
        /// </value>
        public byte[] SamplesData { get; set;}
            
        /// <summary>
        /// Gets the field bytes. This doesn't include the PPI field header.
        /// </summary>
        /// <value>
        /// The bytes.
        /// </value>
        public override byte[] Bytes
        {
            get
            {
                MemoryStream ms = new MemoryStream();
                BinaryWriter writer = new BinaryWriter(ms);
                    
                writer.Write(this.StartingFrequency);
                writer.Write(this.Resolution);
                writer.Write(this.AmplitudeOffset);
                writer.Write(this.AmplitudeResolution);
                writer.Write(this.MaximumRssi);
                writer.Write((ushort) this.SamplesData.Length);
                writer.Write(this.SamplesData);
                    
                return ms.ToArray();
            }    
        }
            
        #endregion Properties

        #region Constructors
        /// <summary>
        /// Initializes a new instance of the <see cref="PacketDotNet.Ieee80211.PpiSpectrum"/> class from the 
        /// provided stream.
        /// </summary>
        /// <remarks>
        /// The position of the BinaryReader's underlying stream will be advanced to the end
        /// of the PPI field.
        /// </remarks>
        /// <param name='br'>
        /// The stream the field will be read from
        /// </param>
        public PpiSpectrum (BinaryReader br)
        {
            this.StartingFrequency = br.ReadUInt32();
            this.Resolution = br.ReadUInt32();
            this.AmplitudeOffset = br.ReadUInt32();
            this.AmplitudeResolution = br.ReadUInt32();
            this.MaximumRssi = br.ReadUInt16();
            var samplesLength = br.ReadUInt16();
            this.SamplesData = br.ReadBytes(samplesLength);
        }
            
        /// <summary>
        /// Initializes a new instance of the <see cref="PacketDotNet.Ieee80211.PpiSpectrum"/> class.
        /// </summary>
        public PpiSpectrum ()
        {
             
        }
            
        #endregion Constructors
    }
}