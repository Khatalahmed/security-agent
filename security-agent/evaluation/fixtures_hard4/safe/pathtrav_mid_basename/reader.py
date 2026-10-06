def read(path):
    with open(path) as fh:                      # looks dangerous in isolation
        return fh.read()
