# -*- coding: utf-8 -*-

"""Main module."""


def quote_line(input_line):
    """
    Wraps ``input_line`` with double quotes.

    Useful for paths with spaces.

    :param input_string: string (if not a string, ``str(input_line)`` applied)
    :returns: string
    """
    return '"' + str(input_line) + '"'
