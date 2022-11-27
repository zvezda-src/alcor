


"""Pygments lexer for our custom shell example sessions.

The lexer support the following custom markup:

  - comments: # this is a comment
  - command lines: '$ ' at the beginning of a line denotes a command
  - variable input: %input% (works in both commands and screen output)
  - otherwise, regular text output from commands will be plain

"""

from pygments.lexer import RegexLexer, bygroups, include
from pygments.token import Name, Text, Generic, Comment
import sphinx


class ShellExampleLexer(RegexLexer):
  name = "ShellExampleLexer"
  aliases = "shell-example"
  filenames = []

  tokens = {
    "root": [
      include("comments"),
      include("userinput"),
      # switch to state input on '$ ' at the start of the line
      (r"^\$ ", Text, "input"),
      (r"\s+", Text),
      (r"[^#%\s\\]+", Text),
      (r"\\", Text),
      ],
    "input": [
      include("comments"),
      include("userinput"),
      (r"[^#%\s\\]+", Generic.Strong),
      (r"\\\n", Generic.Strong),
      (r"\\", Generic.Strong),
      # switch to prev state at non-escaped new-line
      (r"\n", Text, "#pop"),
      (r"\s+", Text),
      ],
    "comments": [
      (r"#.*\n", Comment.Single),
      ],
    "userinput": [
      (r"(\\)(%)", bygroups(None, Text)),
      (r"(%)([^%]*)(%)", bygroups(None, Name.Variable, None)),
      ],
    }


def setup(app):
  version = tuple(map(int, sphinx.__version__.split('.')))
  if version >= (2, 1, 0):
    app.add_lexer("shell-example", ShellExampleLexer)
  else:
    app.add_lexer("shell-example", ShellExampleLexer())
