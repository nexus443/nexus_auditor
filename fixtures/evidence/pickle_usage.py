import pickle


def unsafe_deserialize(payload: bytes):
    # Intended vulnerable fixture for evidence-gate tests.
    return pickle.loads(payload)
