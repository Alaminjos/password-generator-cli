import string
from copy import deepcopy

try:
    from secrets import choice
except Exception:
    from random import choice

from random import shuffle, randint


class PasswordGenerator:
    def __init__(self):
        # length bounds
        self.minlen = 8
        self.maxlen = 16

        # minimum counts for each category
        self.minlchars = 1   # lowercase
        self.minuchars = 1   # uppercase
        self.minnumbers = 1  # numbers
        self.minschars = 1   # special chars

        # exclusions (strings of characters to exclude)
        self.excludelchars = ""
        self.excludeuchars = ""
        self.excludenumbers = ""
        self.excludeschars = ""

        # character pools
        self.lower_chars = string.ascii_lowercase
        self.upper_chars = string.ascii_uppercase
        self.numbers_list = string.digits
        self.schars = [
            "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "-", "_", "=", "+",
            "[", "]", "{", "}", ";", ":", "'", '"', ",", ".", "<", ">", "/", "?", "|", "\\"
        ]

        # combined pool (private)
        self._allchars = (
            list(self.lower_chars) +
            list(self.upper_chars) +
            list(self.numbers_list) +
            list(self.schars)
        )

    def generate(self):
        """Generate a password using default or custom properties"""
        # basic validations
        if (
            self.minlen < 0 or self.maxlen < 0
            or self.minlchars < 0 or self.minuchars < 0
            or self.minnumbers < 0 or self.minschars < 0
        ):
            raise ValueError("Character length should not be negative")

        if self.minlen > self.maxlen:
            raise ValueError("Minimum length cannot be greater than maximum length.")

        # ensure the minimums don't exceed maxlen later on
        collectiveMinLength = (
            self.minlchars + self.minuchars + self.minnumbers + self.minschars
        )
        if collectiveMinLength > self.maxlen:
            raise ValueError("Sum of individual minimums cannot exceed maximum length.")

        # build final_pass with guaranteed category characters (respecting excludes)
        final_pass = []

        # helper to get allowed list for a category
        def allowed(pool, exclude_str):
            return list(set(pool) - set(list(exclude_str)))

        # lowercase
        lc_allowed = allowed(self.lower_chars, self.excludelchars)
        if self.minlchars > 0 and not lc_allowed:
            raise ValueError("No lowercase chars available after exclusions.")
        final_pass += [choice(lc_allowed) for _ in range(self.minlchars)]

        # uppercase
        uc_allowed = allowed(self.upper_chars, self.excludeuchars)
        if self.minuchars > 0 and not uc_allowed:
            raise ValueError("No uppercase chars available after exclusions.")
        final_pass += [choice(uc_allowed) for _ in range(self.minuchars)]

        # numbers
        num_allowed = allowed(self.numbers_list, self.excludenumbers)
        if self.minnumbers > 0 and not num_allowed:
            raise ValueError("No number chars available after exclusions.")
        final_pass += [choice(num_allowed) for _ in range(self.minnumbers)]

        # special chars
        sc_allowed = allowed(self.schars, self.excludeschars)
        if self.minschars > 0 and not sc_allowed:
            raise ValueError("No special chars available after exclusions.")
        final_pass += [choice(sc_allowed) for _ in range(self.minschars)]

        # current length
        current_length = len(final_pass)

        # build the "all chars" pool respecting all exclusions
        all_chars = list(
            set(self._allchars)
            - set(list(self.excludelchars))
            - set(list(self.excludeuchars))
            - set(list(self.excludenumbers))
            - set(list(self.excludeschars))
        )

        if not all_chars and current_length < self.minlen:
            raise ValueError("No characters left to fill password after exclusions.")

        # if we need more characters to reach the randomly chosen length
        if current_length < self.minlen:
            # if current mandatory items exceed minlen, minlen is already satisfied
            randlen = self.minlen
        else:
            randlen = randint(self.minlen, self.maxlen)

        # add random chars until we reach randlen
        if randlen - current_length > 0:
            final_pass += [choice(all_chars) for _ in range(randlen - current_length)]

        # if still shorter than minlen (edge cases), pad from all_chars
        if len(final_pass) < self.minlen:
            final_pass += [choice(all_chars) for _ in range(self.minlen - len(final_pass))]

        # shuffle and return string
        shuffle(final_pass)
        return "".join(final_pass)

    def shuffle_password(self, password, maxlen):
        """Shuffle the given characters to return a password of length maxlen."""
        if maxlen <= 0:
            return ""
        final_pass = [choice(list(password)) for _ in range(int(maxlen))]
        shuffle(final_pass)
        return "".join(final_pass)

    def non_duplicate_password(self, maxlen):
        """Generate a non-duplicate key of given length (no repeated characters)."""
        allchars = deepcopy(self._allchars)
        final_pass = []

        try:
            for _ in range(int(maxlen)):
                character = choice(allchars)
                element_index = allchars.index(character)
                final_pass.append(character)
                allchars.pop(element_index)
        except IndexError:
            # choice(allchars) raises IndexError if sequence is empty
            raise ValueError("Length should be less than or equal to available unique characters.")

        shuffle(final_pass)
        return "".join(final_pass)
# password-generator-cli
