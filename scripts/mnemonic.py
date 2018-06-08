# english.txt: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
# italian.txt: https://github.com/bitcoin/bips/blob/master/bip-0039/italian.txt
class MnemonicDictionaries:
  """Manage dictionary based conversion between index list and mnemonic phrase"""

  def __init__(self, lang = None):
    self.language_files = {
        'en':'english.txt',
        'es':'spanish.txt',
        'it':'italian.txt',
        'ja':'japanese.txt',
        'pt':'portuguese.txt',
        'zh':'chinese_simplified.txt'
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

  def word_indexes_from_entropy(self, entropy):
      words = len(entropy)//11
      return [int(entropy[i*11:(i+1)*11], 2) for i in range(0, words)]

  def encode(self, word_indexes, lang = None):
    if type(word_indexes) == str: # might be binary entropy
      word_indexes = self.word_indexes_from_entropy(word_indexes)
      
    if lang == None: lang = "en"
    self.load_language_if_not_available(lang)

    words = []
    for i in word_indexes:
      word = self.dictionaries[lang][i]
      words.append(word)
    return ' '.join(words)

  def decode(self, mnemonic, lang = None):
    if lang == None: lang = "en"
    self.load_language_if_not_available(lang)
    words = mnemonic.split()
    return [self.dictionaries[lang].index(word) for word in words]

mnemonic_dictionaries = MnemonicDictionaries()

def main():
  mnemonic = "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic"
  lang = "en"
  test_vector = mnemonic_dictionaries.decode(mnemonic, lang)
  assert test_vector == [1268, 535, 810, 685, 433, 811, 1385, 1790, 421, 570, 567, 1313]
  assert mnemonic == mnemonic_dictionaries.encode(test_vector, lang)


if __name__ == "__main__":
  # execute only if run as a script
  main()

