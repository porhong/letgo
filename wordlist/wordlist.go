package wordlist

import (
	"os"
	"sort"
	"strings"
)

// WeightedItem represents an item with a probability weight
type WeightedItem struct {
	Value  string
	Weight int // Higher weight = more common/probable
}

// PasswordGenerator uses probability-based strategies to generate common Thai passwords
type PasswordGenerator struct {
	// Most common global passwords (highest probability)
	commonPasswords []WeightedItem
	// Thai-specific words/phrases
	thaiWords []WeightedItem
	// Thai cities/places
	thaiPlaces []WeightedItem
	// Common number sequences
	numberSequences []WeightedItem
	// Lucky numbers in Thai culture
	luckyNumbers []WeightedItem
	// Years (current and recent)
	years []WeightedItem
	// Common words/phrases
	commonWords []WeightedItem
	// Keyboard patterns
	keyboardPatterns []WeightedItem
}

// NewPasswordGenerator creates a new generator with probability-weighted data
func NewPasswordGenerator() *PasswordGenerator {
	return &PasswordGenerator{
		// Most common passwords globally and in Thailand (ordered by frequency)
		commonPasswords: []WeightedItem{
			{"123456", 100}, // Most common in Thailand
			{"123456789", 95},
			{"12345678", 90},
			{"12345", 85},
			{"1234567", 80},
			{"password", 75},
			{"qwerty", 70},
			{"111111", 65},
			{"123123", 60},
			{"000000", 55},
			{"1234", 50},
			{"123", 45},
			{"admin", 40},
			{"root", 35},
			{"iloveyou", 30},
			{"welcome", 25},
			{"login", 20},
			{"pass", 15},
			{"1234567890", 10},
		},
		// Thai words/phrases commonly used as passwords
		thaiWords: []WeightedItem{
			{"thailand", 100}, // Most common Thai password
			{"bangkok", 95},
			{"sawasdee", 90},
			{"kobkhun", 85},
			{"krub", 80},
			{"ka", 75},
			{"thai", 70},
			{"siam", 65},
			{"phuket", 60},
			{"chiangmai", 55},
			{"pattaya", 50},
			{"sukhothai", 45},
			{"ayutthaya", 40},
		},
		// Thai cities and places
		thaiPlaces: []WeightedItem{
			{"bangkok", 100},
			{"chiangmai", 95},
			{"phuket", 90},
			{"pattaya", 85},
			{"hatyai", 80},
			{"udonthani", 75},
			{"khonkaen", 70},
			{"nakhonratchasima", 65},
			{"suratthani", 60},
			{"rayong", 55},
		},
		// Common number sequences (ordered by frequency)
		numberSequences: []WeightedItem{
			{"123456", 100},
			{"123456789", 95},
			{"12345678", 90},
			{"12345", 85},
			{"1234567", 80},
			{"123123", 75},
			{"111111", 70},
			{"000000", 65},
			{"1234", 60},
			{"123", 55},
			{"1234567890", 50},
			{"654321", 45},
			{"112233", 40},
			{"121212", 35},
			{"123321", 30},
			{"987654", 25},
			{"888888", 20},
			{"999999", 15},
			{"777777", 10},
		},
		// Lucky numbers in Thai culture
		luckyNumbers: []WeightedItem{
			{"7", 100},
			{"9", 95},
			{"8", 90},
			{"13", 85},
			{"24", 80},
			{"77", 75},
			{"88", 70},
			{"99", 65},
			{"777", 60},
			{"888", 55},
			{"999", 50},
			{"7777", 45},
			{"8888", 40},
			{"9999", 35},
		},
		// Years (current and recent)
		years: []WeightedItem{
			{"2025", 100}, // Current year
			{"2024", 95},
			{"2023", 90},
			{"2022", 85},
			{"2021", 80},
			{"2020", 75},
			{"2019", 70},
			{"1990", 65}, // Common birth year
			{"1995", 60},
			{"2000", 55},
			{"2001", 50},
			{"1999", 45},
		},
		// Common words/phrases
		commonWords: []WeightedItem{
			{"password", 100},
			{"admin", 95},
			{"user", 90},
			{"test", 85},
			{"welcome", 80},
			{"login", 75},
			{"pass", 70},
			{"root", 65},
			{"iloveyou", 60},
			{"love", 55},
			{"hello", 50},
			{"welcome123", 45},
			{"password123", 40},
			{"admin123", 35},
		},
		// Keyboard patterns
		keyboardPatterns: []WeightedItem{
			{"qwerty", 100},
			{"qwerty123", 95},
			{"qwertyuiop", 90},
			{"asdfgh", 85},
			{"asdfgh123", 80},
			{"zxcvbn", 75},
			{"qwertyui", 70},
			{"1qaz2wsx", 65},
			{"qazwsx", 60},
			{"qwerty1", 55},
		},
	}
}

// Generate creates a file with probability-based common Thai passwords for 2025
// If count > 0, only the first 'count' passwords will be generated
func Generate(filename string, count int) error {
	generator := NewPasswordGenerator()
	passwords := generator.GeneratePasswords()

	// Limit to count if specified
	if count > 0 && count < len(passwords) {
		passwords = passwords[:count]
	}

	content := strings.Join(passwords, "\n")
	return os.WriteFile(filename, []byte(content), 0644)
}

// GeneratePasswords generates passwords using probability-based strategies
func (g *PasswordGenerator) GeneratePasswords() []string {
	passwords := make(map[string]int) // Use map to avoid duplicates and track probability

	// Strategy 1: Pure common passwords (highest probability)
	g.addCommonPasswords(passwords)

	// Strategy 2: Thai words/phrases (very common in Thailand)
	g.addThaiWords(passwords)

	// Strategy 3: Thai places + numbers
	g.addThaiPlacesWithNumbers(passwords)

	// Strategy 4: Common words + numbers
	g.addCommonWordsWithNumbers(passwords)

	// Strategy 5: Number sequences (very common)
	g.addNumberSequences(passwords)

	// Strategy 6: Lucky numbers (Thai cultural pattern)
	g.addLuckyNumberPatterns(passwords)

	// Strategy 7: Years (birth years, current year)
	g.addYearPatterns(passwords)

	// Strategy 8: Keyboard patterns
	g.addKeyboardPatterns(passwords)

	// Strategy 9: Combinations (word + number, etc.)
	g.addCombinations(passwords)

	// Strategy 10: Substitutions (a->@, i->1, etc.)
	g.addSubstitutions(passwords)

	// Strategy 11: Thai words with common suffixes
	g.addThaiWordsWithSuffixes(passwords)

	// Strategy 12: Reversed patterns
	g.addReversedPatterns(passwords)

	// Convert to sorted slice by probability (descending)
	return g.sortByProbability(passwords)
}

// addCommonPasswords adds pure common passwords
func (g *PasswordGenerator) addCommonPasswords(passwords map[string]int) {
	for _, item := range g.commonPasswords {
		passwords[item.Value] = item.Weight
	}
}

// addThaiWords adds Thai words/phrases
func (g *PasswordGenerator) addThaiWords(passwords map[string]int) {
	for _, item := range g.thaiWords {
		passwords[item.Value] = item.Weight
		// Add with numbers
		for _, num := range g.numberSequences {
			if num.Weight >= 80 {
				passwords[item.Value+num.Value] = (item.Weight + num.Weight) / 2
			}
		}
		// Add with lucky numbers
		for _, lucky := range g.luckyNumbers {
			if lucky.Weight >= 80 {
				passwords[item.Value+lucky.Value] = (item.Weight + lucky.Weight) / 2
			}
		}
	}
}

// addThaiPlacesWithNumbers adds Thai places with numbers
func (g *PasswordGenerator) addThaiPlacesWithNumbers(passwords map[string]int) {
	for _, place := range g.thaiPlaces {
		if place.Weight >= 70 {
			// Pure place
			passwords[place.Value] = place.Weight

			// Place + numbers
			for _, num := range g.numberSequences {
				if num.Weight >= 70 {
					passwords[place.Value+num.Value] = (place.Weight + num.Weight) / 2
				}
			}

			// Place + lucky numbers
			for _, lucky := range g.luckyNumbers {
				if lucky.Weight >= 70 {
					passwords[place.Value+lucky.Value] = (place.Weight + lucky.Weight) / 2
				}
			}

			// Place + year
			for _, year := range g.years {
				if year.Weight >= 90 {
					passwords[place.Value+year.Value] = (place.Weight + year.Weight) / 2
				}
			}
		}
	}
}

// addCommonWordsWithNumbers adds common words with numbers
func (g *PasswordGenerator) addCommonWordsWithNumbers(passwords map[string]int) {
	for _, word := range g.commonWords {
		if word.Weight >= 60 {
			// Pure word
			passwords[word.Value] = word.Weight

			// Word + numbers
			for _, num := range g.numberSequences {
				if num.Weight >= 70 {
					passwords[word.Value+num.Value] = (word.Weight + num.Weight) / 2
				}
			}

			// Word + lucky numbers
			for _, lucky := range g.luckyNumbers {
				if lucky.Weight >= 70 {
					passwords[word.Value+lucky.Value] = (word.Weight + lucky.Weight) / 2
				}
			}
		}
	}
}

// addNumberSequences adds pure number sequences
func (g *PasswordGenerator) addNumberSequences(passwords map[string]int) {
	for _, item := range g.numberSequences {
		passwords[item.Value] = item.Weight
	}
}

// addLuckyNumberPatterns adds lucky number patterns
func (g *PasswordGenerator) addLuckyNumberPatterns(passwords map[string]int) {
	for _, lucky := range g.luckyNumbers {
		passwords[lucky.Value] = lucky.Weight
		// Repeat lucky numbers
		if len(lucky.Value) <= 2 {
			passwords[lucky.Value+lucky.Value] = lucky.Weight - 10
			passwords[lucky.Value+lucky.Value+lucky.Value] = lucky.Weight - 20
		}
	}
}

// addYearPatterns adds year patterns
func (g *PasswordGenerator) addYearPatterns(passwords map[string]int) {
	for _, year := range g.years {
		if year.Weight >= 80 {
			// Pure year
			passwords[year.Value] = year.Weight

			// Year + common sequences
			for _, seq := range g.numberSequences {
				if seq.Weight >= 80 {
					passwords[year.Value+seq.Value] = (year.Weight + seq.Weight) / 2
					passwords[seq.Value+year.Value] = (year.Weight + seq.Weight) / 2
				}
			}
		}
	}
}

// addKeyboardPatterns adds keyboard patterns
func (g *PasswordGenerator) addKeyboardPatterns(passwords map[string]int) {
	for _, pattern := range g.keyboardPatterns {
		passwords[pattern.Value] = pattern.Weight
	}
}

// addCombinations adds common combinations
func (g *PasswordGenerator) addCombinations(passwords map[string]int) {
	// Common word combinations
	combinations := []struct {
		prefix string
		suffix string
		weight int
	}{
		{"thai", "land", 90},
		{"bangkok", "123", 85},
		{"thailand", "123", 80},
		{"password", "123", 75},
		{"admin", "123", 70},
		{"user", "123", 65},
		{"test", "123", 60},
		{"welcome", "123", 55},
		{"love", "you", 50},
		{"ilove", "you", 45},
	}

	for _, combo := range combinations {
		passwords[combo.prefix+combo.suffix] = combo.weight
	}
}

// addSubstitutions adds passwords with common character substitutions
func (g *PasswordGenerator) addSubstitutions(passwords map[string]int) {
	substitutions := map[string]string{
		"a": "@",
		"i": "1",
		"e": "3",
		"o": "0",
		"s": "$",
		"l": "1",
	}

	// Apply substitutions to common passwords
	commonWords := []string{"password", "admin", "thailand", "bangkok", "welcome", "iloveyou"}
	for _, word := range commonWords {
		// Apply common substitutions
		subbed := word
		subbed = strings.ReplaceAll(subbed, "a", "@")
		subbed = strings.ReplaceAll(subbed, "i", "1")
		subbed = strings.ReplaceAll(subbed, "e", "3")
		subbed = strings.ReplaceAll(subbed, "o", "0")
		subbed = strings.ReplaceAll(subbed, "s", "$")
		if subbed != word {
			passwords[subbed] = 50
			// Add with numbers
			for _, num := range g.numberSequences {
				if num.Weight >= 80 {
					passwords[subbed+num.Value] = 40
				}
			}
		}

		// Partial substitution (only first letter)
		if len(word) > 0 {
			firstChar := string(word[0])
			if sub, ok := substitutions[firstChar]; ok {
				partialSub := sub + word[1:]
				passwords[partialSub] = 45
			}
		}
	}
}

// addThaiWordsWithSuffixes adds Thai words with common suffixes
func (g *PasswordGenerator) addThaiWordsWithSuffixes(passwords map[string]int) {
	topThaiWords := []string{"thailand", "bangkok", "sawasdee", "thai"}
	suffixes := []string{"123", "1234", "12345", "123456", "2025", "2024"}

	for _, word := range topThaiWords {
		for _, suffix := range suffixes {
			passwords[word+suffix] = 60
		}
		// Add with underscore
		for _, suffix := range suffixes {
			passwords[word+"_"+suffix] = 55
		}
	}
}

// addReversedPatterns adds reversed common patterns
func (g *PasswordGenerator) addReversedPatterns(passwords map[string]int) {
	// Reverse common sequences
	reversals := []string{
		"654321",
		"987654321",
		"4321",
		"321",
	}

	for _, rev := range reversals {
		passwords[rev] = 40
		// Add with words
		passwords["thailand"+rev] = 35
		passwords["bangkok"+rev] = 30
	}
}

// sortByProbability converts map to sorted slice by probability (descending)
func (g *PasswordGenerator) sortByProbability(passwords map[string]int) []string {
	type passProb struct {
		password string
		prob     int
	}

	var passList []passProb
	for password, prob := range passwords {
		passList = append(passList, passProb{password, prob})
	}

	// Sort by probability descending
	sort.Slice(passList, func(i, j int) bool {
		return passList[i].prob > passList[j].prob
	})

	result := make([]string, len(passList))
	for i, item := range passList {
		result[i] = item.password
	}

	return result
}
