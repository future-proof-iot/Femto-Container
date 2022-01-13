project('femto-containers', 'c', default_options : ['werror=true'])

incdir = include_directories('include')
lib = library('fc', 'src/bpf.c', 'src/jumptable.c', 'src/verify.c', include_directories : incdir) 
