#!/bin/bash
stelftools_path=$(pwd)
ida_install_path=$1

if [ $# != 1 ]; then
  echo "Please input the directory in which you installed IDA Pro"
  exit 1
fi

# Symlink the plugin entry point so IDA finds it; func_ident.py and the
# libfunc_* modules are imported via sys.path manipulation inside the
# plugin (the parent of the resolved file is added to sys.path), so we
# only need to symlink the single entry script.
pushd $ida_install_path/plugins
ln -s $stelftools_path/plugins/ida.py stelftools.py
popd
