


"""Module containing backported language/library functionality.

"""

import itertools
import operator

try:
  # pylint: disable=F0401
  import functools
except ImportError:
  functools = None

try:
  # pylint: disable=F0401
  import roman
except ImportError:
  roman = None


def _all(seq):
  """Returns True if all elements in the iterable are True.

  """
  for _ in itertools.filterfalse(bool, seq):
    return False
  return True


def _any(seq):
  """Returns True if any element of the iterable are True.

  """
  for _ in filter(bool, seq):
    return True
  return False


try:
  # pylint: disable=E0601
  # pylint: disable=W0622
  all = all
except NameError:
  all = _all

try:
  # pylint: disable=E0601
  # pylint: disable=W0622
  any = any
except NameError:
  any = _any


def partition(seq, pred=bool): # pylint: disable=W0622
  """Partition a list in two, based on the given predicate.

  """
  return (list(filter(pred, seq)),
          list(itertools.filterfalse(pred, seq)))


def _partial(func, *args, **keywords): # pylint: disable=W0622
  """Decorator with partial application of arguments and keywords.

  This function was copied from Python's documentation.

  """
  def newfunc(*fargs, **fkeywords):
    newkeywords = keywords.copy()
    newkeywords.update(fkeywords)
    return func(*(args + fargs), **newkeywords)

  newfunc.func = func
  newfunc.args = args
  newfunc.keywords = keywords
  return newfunc


if functools is None:
  partial = _partial
else:
  partial = functools.partial


def RomanOrRounded(value, rounding, convert=True):
  """Try to round the value to the closest integer and return it as a roman
  numeral. If the conversion is disabled, or if the roman module could not be
  loaded, round the value to the specified level and return it.

  @type value: number
  @param value: value to convert
  @type rounding: integer
  @param rounding: how many decimal digits the number should be rounded to
  @type convert: boolean
  @param convert: if False, don't try conversion at all
  @rtype: string
  @return: roman numeral for val, or formatted string representing val if
           conversion didn't succeed

  """
  def _FormatOutput(val, r):
    format_string = "%0." + str(r) + "f"
    return format_string % val

  if roman is not None and convert:
    try:
      return roman.toRoman(round(value, 0))
    except roman.RomanError:
      return _FormatOutput(value, rounding)
  return _FormatOutput(value, rounding)


def TryToRoman(val, convert=True):
  """Try to convert a value to roman numerals

  If the roman module could be loaded convert the given value to a roman
  numeral. Gracefully fail back to leaving the value untouched.

  @type val: integer
  @param val: value to convert
  @type convert: boolean
  @param convert: if False, don't try conversion at all
  @rtype: string or typeof(val)
  @return: roman numeral for val, or val if conversion didn't succeed

  """
  if roman is not None and convert:
    try:
      return roman.toRoman(val)
    except roman.RomanError:
      return val
  else:
    return val


def UniqueFrozenset(seq):
  """Makes C{frozenset} from sequence after checking for duplicate elements.

  @raise ValueError: When there are duplicate elements

  """
  if isinstance(seq, (list, tuple)):
    items = seq
  else:
    items = list(seq)

  result = frozenset(items)

  if len(items) != len(result):
    raise ValueError("Duplicate values found")

  return result


fst = operator.itemgetter(0)

snd = operator.itemgetter(1)
