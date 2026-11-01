namespace NokitaKaze.TornadoCashEncryptedNote
{
    /// <summary>
    /// The exception thrown when a note, address, private key, or ciphertext is rejected.
    /// </summary>
    public class EncryptedNoteException : System.Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="EncryptedNoteException"/> class with a message that describes the failure.
        /// </summary>
        /// <param name="message">The message that describes the failure.</param>
        public EncryptedNoteException(string message) : base(message)
        {
        }
    }
}
