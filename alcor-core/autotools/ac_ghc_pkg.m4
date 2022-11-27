


AC_DEFUN([AC_GHC_PKG_CHECK],[
    if test -z $GHC_PKG; then
        AC_MSG_ERROR([GHC_PKG not defined])
    fi
    AC_MSG_CHECKING([haskell library $1])
    if test -n "$4"; then
      GHC_PKG_RESULT=$($GHC_PKG --simple-output list '$1'|tail -n1)
    else
      GHC_PKG_RESULT=$($GHC_PKG latest '$1' 2>/dev/null)
    fi
    if test -n "$GHC_PKG_RESULT"; then
      AC_MSG_RESULT($GHC_PKG_RESULT)
      $2
    else
      AC_MSG_RESULT([no])
      $3
    fi
])


AC_DEFUN([AC_GHC_PKG_REQUIRE],[
    AC_GHC_PKG_CHECK($1, [],
                     [AC_MSG_FAILURE([Required Haskell module $1 not found])],
                     $2)
])
