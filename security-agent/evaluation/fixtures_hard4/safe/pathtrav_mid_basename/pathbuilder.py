import os


def make(name):
    # basename strips any directory components; join anchors under a fixed base.
    return os.path.join("/srv/docs", os.path.basename(name))
