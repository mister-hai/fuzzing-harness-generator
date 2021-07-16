
class CodeQLMeta(object):
    def __init_(self):
        pass
    
    def createdatabase(self):
        pass

    def codeqlquery(self,query,fileoutputname):
        command = {'codeqlquery': {
                        'command' : 'codeql query run {} -o {} {} -d {}'.format( 
                                    query,
                                    '{}.bqrs'.format(fileoutputname),
                                    self.codeqloutputdir),
                        'info'    :"runs a codeql query",
                        'success' :"success message",
                        'failure' : 'failure message'
                        }
                    }
        
    def bqrsdecode(self):
        command = "codeql bqrs decode --format=csv {} onearg.bqrs -o {bqrsoutput} {outputcsvfile}"
        pass
