# -*- mode: python -*-
a = Analysis(['vseutil.py'],
             pathex=['C:\\Users\\XVassilakopoulos.ODYSSEY\\Documents\\pyinstaller-2.0\\eclipse_work\\vse88x'],
             hiddenimports=[],
             hookspath=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name=os.path.join('dist', 'vseutil.exe'),
          debug=False,
          strip=None,
          upx=True,
          console=True , icon='loo.ico')
