class MnemonicDictionaries:
  """Manage dictionary based conversion between index list and mnemonic phrase"""

  def __init__(self):
    # https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
    # https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt
    self.language_files = {
        'en':'english.txt',
        'it':'italian.txt'
    }
    languages = self.language_files.keys()
    # empy dictionaries
    self.dictionaries = dict(zip(languages, [None]*len(languages)))

  def load_language_if_not_available(self, lang):
    assert lang in self.dictionaries.keys(), "unknown language"

    if self.dictionaries[lang] == None:
      filename = self.language_files[lang]
      #path = os.path.join(os.path.dirname(__file__),
      #                    folder,
      #                    filename)
      path = filename
      lines = open(path, 'r').readlines()
      self.dictionaries[lang] = [line[:-1] for line in lines]

  def indexes_from_entropy(self, entropy):
      assert int(entropy, 2), "entropy must be a binary string"
      words = len(entropy)//11
      return [int(entropy[i*11:(i+1)*11], 2) for i in range(0, words)]

  def mnemonic_from_indexes(self, indexes, lang = "en"):
    self.load_language_if_not_available(lang)

    words = []
    for i in indexes:
      word = self.dictionaries[lang][i]
      words.append(word)
    return ' '.join(words)

  def indexes_from_mnemonic(self, mnemonic, lang = "en"):
    self.load_language_if_not_available(lang)

    words = mnemonic.split()
    indexes = [self.dictionaries[lang].index(word) for word in words]
    return indexes

mnemonic_dict = MnemonicDictionaries()

def main():
  mnemonic = "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
  lang = "en"
  test_vector = mnemonic_dict.indexes_from_mnemonic(mnemonic, lang)
  assert test_vector == [1268, 535, 810, 685, 433, 811, 1385, 1790, 421, 570, 567, 1313]
  assert mnemonic == mnemonic_dict.mnemonic_from_indexes(test_vector, lang)


if __name__ == "__main__":
  # execute only if run as a script
  main()
