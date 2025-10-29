import os
import stat

# Cambiar permisos a solo lectura
os.chmod('admin_private_key.pem', stat.S_IREAD)
os.chmod('admin_public_key.pem', stat.S_IREAD)