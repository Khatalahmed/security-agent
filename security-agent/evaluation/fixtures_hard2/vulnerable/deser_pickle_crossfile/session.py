"""Session helper. Looks like generic state loading; pickle makes it RCE."""
import pickle


def load_state(raw):
    # pickle.loads executes reducers embedded in the byte stream, so untrusted
    # bytes mean arbitrary code execution - not merely "parsing".
    return pickle.loads(raw)                     # SINK
