import os

def writecodeqlfile(filetowrite):
    os.open()


scanoperation = dict

scanoperation({'multiargfunc' : '''import cpp

Type getParameterTypeElement(Parameter p) {
  result = p.getUnspecifiedType()
  or
  result = getParameterTypeElement(p).(PointerType).getBaseType().getUnspecifiedType()
}

Type getParameterBaseType(Parameter p) {
  result = getParameterTypeElement(p) and not result instanceof PointerType
}

from Function f, Type t, string g 
where not exists(Parameter p | p = f.getAParameter() | getParameterBaseType(p) instanceof Struct) and
t = f.getAParameter().getType() and
g = f.getType().toString()
select f, t, g
'''})
###############################################################################
scanoperation({'multiarglocation': '''import cpp

Type getParameterTypeElement(Parameter p) {
  result = p.getUnspecifiedType()
  or
  result = getParameterTypeElement(p).(PointerType).getBaseType().getUnspecifiedType()
}

Type getParameterBaseType(Parameter p) {
  result = getParameterTypeElement(p) and not result instanceof PointerType
}

from Function f, Type t, string g 
where not exists(Parameter p | p = f.getAParameter() | getParameterBaseType(p) instanceof Struct) and
t = f.getAParameter().getType() and
g = min(f.getADeclarationLocation().getContainer().toString())
select f, t, g
'''})
###############################################################################
scanoperation({'oneargfunc':'''import cpp

from Function f, Variable v, string x, string t, string g
where
	f.getNumberOfParameters() = 1 and
	v = f.getParameter(0) and
	not (v.getUnspecifiedType() instanceof Struct) and
	not (v.getUnspecifiedType().(PointerType).getBaseType+().getUnspecifiedType() instanceof Struct) and
	x = v.getUnspecifiedType().toString() and
	x != "..(*)(..)" and
	g = f.getType().toString() and
	t = v.getType().toString()
select f, t, g

'''})

scanoperation({'onearglocation': '''import cpp

from Function f, Variable v, string x, string g, string t
where
	f.getNumberOfParameters() = 1 and
	v = f.getParameter(0) and
	not (v.getUnspecifiedType() instanceof Struct) and
	not (v.getUnspecifiedType().(PointerType).getBaseType+().getUnspecifiedType() instanceof Struct) and
	x = v.getUnspecifiedType().toString() and
	x != "..(*)(..)" and
	g = min(f.getADeclarationLocation().getContainer().toString()) and
	t = v.getType().toString()
select f, t, g
'''})