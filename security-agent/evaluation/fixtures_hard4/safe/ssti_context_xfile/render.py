from flask import render_template_string


def show(name):
    # Fixed template; user value is bound data (autoescaped), never template code.
    return render_template_string("<h1>Hello {{ n }}</h1>", n=name)   # safe use
