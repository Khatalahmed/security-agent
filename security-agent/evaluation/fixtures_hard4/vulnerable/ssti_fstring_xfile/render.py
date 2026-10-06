from flask import render_template_string


def show(name):
    # User text becomes part of the template program text -> SSTI.
    return render_template_string("<h1>Hello " + name + "</h1>")   # SINK
