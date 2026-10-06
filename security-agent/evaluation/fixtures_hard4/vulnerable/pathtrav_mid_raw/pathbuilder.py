def make(name):
    # No basename / anchoring: '../' survives (contrast: safe twin basenames).
    return "/srv/docs/" + name
