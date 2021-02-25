/**
  * @name 41_fopen_to_alloca_taint
  * @description Track taint from fopen to alloca.
  * @kind path-problem
  * @problem.severity warning
  */

 import cpp
 import semmle.code.cpp.rangeanalysis.SimpleRangeAnalysis
 import semmle.code.cpp.dataflow.TaintTracking
 import semmle.code.cpp.models.interfaces.DataFlow
 import semmle.code.cpp.controlflow.Guards
 import DataFlow::PathGraph
 

 predicate isSafeAllocaCall(FunctionCall allocaCall) {
    exists( FunctionCall fc, GuardCondition gc,
    DataFlow::Node source, DataFlow::Node sink, 
    BasicBlock b |
    fc.getTarget().getName() = "__libc_use_alloca" 
    and b.contains(fc)
    and gc.controls(allocaCall.getBasicBlock(), _)
    and DataFlow::localFlow(source, sink)
    and source.asExpr() = b.getANode() 
    and sink.asExpr() = gc.getAChild*()
    )
}

predicate isOOBAllocaCall(FunctionCall allocaCall) {
    exists(Expr sizearg |
        sizearg = allocaCall.getArgument(0).getFullyConverted()
        and ( upperBound(sizearg) >= 65536
        or lowerBound(sizearg) < 0 )
    )
}

 // Track taint through `__strnlen`.
 class StrlenFunction extends DataFlowFunction {
   StrlenFunction() { this.getName().matches("%str%len%") }
 
   override predicate hasDataFlow(FunctionInput i, FunctionOutput o) {
     i.isParameter(0) and o.isReturnValue()
   }
 }
 
 // Track taint through `__getdelim`.
 class GetDelimFunction extends DataFlowFunction {
   GetDelimFunction() { this.getName().matches("%get%delim%") }
 
   override predicate hasDataFlow(FunctionInput i, FunctionOutput o) {
     i.isParameter(3) and o.isParameterDeref(0)
   }
 }
 
 class Config extends TaintTracking::Configuration {
   Config() { this = "fopen_to_alloca_taint" }
 
   override predicate isSource(DataFlow::Node source) {
     exists( FunctionCall fopencall |
        fopencall.getTarget().getName() = "_IO_new_fopen"
        and source.asExpr() = fopencall
     )
   }
 
   override predicate isSink(DataFlow::Node sink) {
    exists( FunctionCall allocaCall, Expr sizearg |
        allocaCall.getTarget().getName() = "__builtin_alloca"
        and isOOBAllocaCall(allocaCall)
        and not isSafeAllocaCall(allocaCall)
        and sizearg = allocaCall.getArgument(0).getFullyConverted()
        and sink.asExpr() = sizearg 
    )
   }
 }

 from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
 where cfg.hasFlowPath(source, sink)
 select sink, source, sink, "fopen flows to alloca"




