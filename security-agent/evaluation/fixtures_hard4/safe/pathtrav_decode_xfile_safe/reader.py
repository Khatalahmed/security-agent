def read(name):
    # `name` is already decoded and basename-reduced upstream; anchored read.
    with open("/srv/docs/" + name) as fh:       # looks dangerous in isolation
        return fh.read()
