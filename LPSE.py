from math import ceil, sqrt
import sys
import string


COMPONENT_WEIGHT = {
    'n_digits': 1,
    'n_lowercase': 1,
    'n_uppercase': 2,
    'n_special_chars': 3,
    'password_length': 1,
}


def cosine_similarity(x: str, y: str) -> float:
    numerator = 0
    for xi, yi in zip(x, y):
        numerator += xi * yi

    sum_x_squared = sum(xi**2 for xi in x)
    sum_y_squared = sum(yi**2 for yi in y)

    denomerator = sqrt(sum_x_squared * sum_y_squared)
    return numerator / denomerator


def cosine_length_similarity(x: str, y: str) -> float:
    cos = cosine_similarity(x, y)
    x_length = sqrt(sum(xi**2 for xi in x))
    y_length = sqrt(sum(yi**2 for yi in y))

    return cos * min(x_length, y_length) / max(x_length, y_length)


def pass_vector(password: str):
    pass_values = {
        'n_digits': sum(c.isdigit() for c in password),
        'n_lowercase': sum(c.islower() for c in password),
        'n_uppercase': sum(c.isupper() for c in password),
        'n_special_chars': sum(not c.isalnum for c in password),
        'password_length': len(password),
    }
    return [pass_values[k] * COMPONENT_WEIGHT[k] for k in COMPONENT_WEIGHT.keys()]

def classify(cls_score: float) -> string:
    if cls_score >= 0.4:
        return 'strong'
    if cls_score <= 0.19:
        return 'weak'

    return 'medium'


def LPSE(password: str) -> tuple[float, str]:
    spv = strong_pass_vector()
    p_vector = pass_vector(password)
    # TODO(ASN): 3.4.2. Improved password-distance similarity
    cls = cosine_length_similarity(spv, p_vector)
    return cls, classify(cls)


def average_strength_value(func, pass_length=18, alphabeth=string.printable):
    alphabeth_length = len(alphabeth)  # 100 in string.printable
    return ceil(sum(func(c) for c in alphabeth) / alphabeth_length * pass_length)


def not_alpha(c: str) -> bool:
    return not c.isalpha()


def strong_pass_vector(pass_length=18):  # A random password should have this vector
    pass_values = {
        'n_digits': average_strength_value(str.isdigit),
        'n_lowercase': average_strength_value(str.islower),
        'n_uppercase': average_strength_value(str.isupper),
        'n_special_chars': average_strength_value(not_alpha),
        'password_length': pass_length,
    }
    return [pass_values[k] * COMPONENT_WEIGHT[k] for k in COMPONENT_WEIGHT.keys()]


if __name__ == '__main__':
    print(LPSE(sys.argv[1]))
else:
    print(LPSE('L33tP4ssw*rd'))