import cpp
import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis

/* Return only large or negative allocations */

from FunctionCall fc
where fc.getTarget().getName() = "__builtin_alloca" 
and ( upperBound(fc.getArgument(0).getFullyConverted()) >= 65536
    or lowerBound(fc.getArgument(0).getFullyConverted()) < 0
)
select fc