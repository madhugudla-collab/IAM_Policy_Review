def classify(score):
    if score > 90:
        return "A"
    elif score > 80:
        return "B"
    else:
        return "C"

print(classify(90))
