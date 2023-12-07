from securesystemslib.signer import Key, Signer


class SignerStore:
    """Generic signer store.

    Provides method to load and cache signer for passed public key, using a URI
    configured in a custom field of the passed key.

    """

    def __init__(self):
        self._signers: dict[str, Signer] = {}

    def get(self, key: Key) -> Signer:
        """Return signer for passed key.

        NOTE:
        expect key to have an ``unrecognized_fields["x-rstuf-online-key-uri"]``,
        field with a URI, which must encode all information for the Signer.

        Secrets are not in the scope of SignerStore and must be provided ambiently, e.g. by
        using environment variables to authenticate with a Cloud KMS.

        If keys are loaded from file, they must be unencrypted, and should use
        platform mechanisms to handle secrets.
        """

        # If signer not in cache, load it using config
        if key.keyid not in self._signers:
            uri = key.unrecognized_fields["x-rstuf-online-key-uri"]
            self._signers[key.keyid] = Signer.from_priv_key_uri(uri, key)

        return self._signers[key.keyid]
