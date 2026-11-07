# Lead scoring for the SDR team.
# We rank open leads by expected value so reps call the highest-priority ones first
# and spend their hours where the impact is greatest. Score = fit * intent * deal size.
def score(lead):
    fit = {"enterprise": 1.0, "mid": 0.7, "smb": 0.4}[lead.segment]
    intent = min(lead.site_visits_7d / 10, 1.0)
    return fit * intent * lead.est_deal_size

def prioritize(leads, top=25):
    ranked = sorted(leads, key=score, reverse=True)
    # The top of this list is the day's call sheet; the rest roll over to tomorrow.
    return ranked[:top]
