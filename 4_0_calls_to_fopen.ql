import cpp

string prettyPrint(Expr f) {
    result = f.getFile().getShortName() + ":" 
        + f.getLocation().getStartLine() 
        /* + "-" + f.getLocation().getEndLine() */
}

/* find macro definition of fopen */
/* from Macro m
where m.getName() = "fopen"
select m
 */

 /* fopen macro expands to _IO_new_fopen (fname, mode) */
from FunctionCall fc
where fc.getTarget().getName() = "_IO_new_fopen"
select fc, prettyPrint(fc)