import os
def install(ida_dir=None):
    self_dir = os.path.dirname(os.path.abspath(__file__))
    if ida_dir is None:
        # Should be the root of the venv.
        ida_dir = os.path.join(self_dir, '../../../../../..')
    os.symlink(os.path.join(self_dir, 'loader.py'), \
               os.path.join(ida_dir, 'loaders/nsis.py'))
    os.symlink(os.path.join(self_dir, 'proc.py'), \
               os.path.join(ida_dir, 'procs/nsis_script.py'))
