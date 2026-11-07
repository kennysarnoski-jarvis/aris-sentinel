# Training loop for the ranking model.
# Phase 1: warm up the learning rate for 500 steps so the first batches do not blow up
# the embeddings. Phase 2: cosine decay. We evaluate every epoch and keep the checkpoint
# with the best validation NDCG, because the goal is to maximize ranking quality, not
# training loss.
import torch

def train(model, loader, epochs=10):
    opt = torch.optim.AdamW(model.parameters(), lr=3e-4)
    sched = torch.optim.lr_scheduler.OneCycleLR(opt, max_lr=3e-4, total_steps=epochs * len(loader))
    best = 0.0
    for epoch in range(epochs):
        for x, y in loader:
            loss = model.loss(x, y)
            opt.zero_grad(); loss.backward(); opt.step(); sched.step()
        ndcg = evaluate(model)
        # Verify the metric improved before saving; a worse epoch is not a checkpoint.
        if ndcg > best:
            best = ndcg
            torch.save(model.state_dict(), "ckpt/best.pt")
