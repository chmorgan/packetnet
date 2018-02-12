using System.IO;

namespace PacketDotNet.Ieee80211
{
    /// <summary>
    /// The PPI Capture Info field has been assigned a PPI field type but currently has no defined
    /// field body.
    /// </summary>
    public class PpiCaptureInfo : PpiField
    {
        #region Properties

        /// <summary>Type of the field</summary>
        public override PpiFieldType FieldType => PpiFieldType.PpiCaptureInfo;

        /// <summary>
        /// Gets the length of the field data.
        /// </summary>
        /// <value>
        /// The length.
        /// </value>
        public override int Length => 0;

        /// <summary>
        /// Gets the field bytes. This doesn't include the PPI field header.
        /// </summary>
        /// <value>
        /// The bytes.
        /// </value>
        public override byte[] Bytes => new byte[0];

        #endregion Properties

        #region Constructors
        /// <summary>
        /// Initializes a new instance of the <see cref="PacketDotNet.Ieee80211.PpiCaptureInfo"/> class from the 
        /// provided stream.
        /// </summary>
        /// <remarks>
        /// The position of the BinaryReader's underlying stream will be advanced to the end
        /// of the PPI field.
        /// </remarks>
        /// <param name='br'>
        /// The stream the field will be read from
        /// </param>
        public PpiCaptureInfo (BinaryReader br)
        {
        }
            
        /// <summary>
        /// Initializes a new instance of the <see cref="PacketDotNet.Ieee80211.PpiCaptureInfo"/> class.
        /// </summary>
        public PpiCaptureInfo()
        {
             
        }

        #endregion Constructors
    }
}