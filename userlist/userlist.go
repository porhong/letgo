package userlist

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

// UsernameGenerator uses probability-based strategies to generate common Thai usernames
type UsernameGenerator struct {
	// Most common Thai nicknames (highest probability)
	nicknames []WeightedItem
	// Common Thai male names
	maleNames []WeightedItem
	// Common Thai female names
	femaleNames []WeightedItem
	// Lucky numbers in Thai culture (with probability weights)
	luckyNumbers []WeightedItem
	// Common number sequences
	numberSequences []WeightedItem
	// Common separators/patterns
	separators []WeightedItem
	// System/admin usernames
	systemUsers []WeightedItem
	// Thai words/terms
	thaiWords []WeightedItem
}

// NewUsernameGenerator creates a new generator with probability-weighted data
func NewUsernameGenerator() *UsernameGenerator {
	return &UsernameGenerator{
		// Nicknames ordered by popularity (weight = probability score)
		nicknames: []WeightedItem{
			{"nong", 100}, // Most common
			{"aom", 95},
			{"ploy", 90},
			{"fah", 85},
			{"nam", 80},
			{"mint", 75},
			{"pim", 70},
			{"pimmy", 65},
			{"pee", 60},
			{"nongfah", 55},
			{"nongploy", 50},
			{"nongmint", 45},
			{"nongpim", 40},
		},
		// Male names ordered by commonality
		maleNames: []WeightedItem{
			{"somchai", 90},
			{"somsak", 85},
			{"prasert", 80},
			{"wichai", 75},
			{"niran", 70},
			{"surat", 65},
			{"chai", 95}, // Short, very common
			{"nattapong", 60},
			{"pichai", 55},
			{"thanawat", 50},
			{"kittisak", 45},
			{"narong", 40},
			{"somkiat", 35},
			{"wichit", 30},
			{"sombun", 25},
			{"somphon", 20},
			{"sombat", 15},
			{"udom", 10},
			{"wichian", 5},
		},
		// Female names ordered by commonality
		femaleNames: []WeightedItem{
			{"anong", 90},
			{"boonsri", 85},
			{"chailai", 80},
			{"chomchai", 75},
			{"lawan", 70},
			{"naree", 65},
			{"wanida", 60},
			{"siriporn", 55},
			{"supaporn", 50},
			{"somchit", 45},
			{"nittaya", 40},
			{"prani", 35},
			{"kanchana", 30},
			{"sukanya", 25},
			{"mali", 20},
			{"wilai", 15},
			{"watsana", 10},
			{"rattana", 5},
			{"wanphen", 5},
		},
		// Lucky numbers with probability (most common first)
		luckyNumbers: []WeightedItem{
			{"7", 100}, // Most lucky
			{"9", 95},
			{"8", 90},
			{"13", 85},
			{"24", 80},
			{"88", 75},
			{"99", 70},
			{"77", 65},
			{"888", 60},
			{"999", 55},
			{"2025", 50}, // Current year
			{"2024", 45},
			{"2023", 40},
		},
		// Common number sequences
		numberSequences: []WeightedItem{
			{"123", 100}, // Most common
			{"456", 80},
			{"789", 70},
			{"000", 60},
			{"111", 55},
			{"222", 50},
			{"333", 45},
			{"444", 40},
			{"555", 35},
			{"666", 30},
			{"777", 25},
			{"888", 20},
			{"999", 15},
		},
		// Separators/patterns
		separators: []WeightedItem{
			{"", 100}, // No separator (most common)
			{"_", 80},
			{".", 70},
			{"-", 60},
			{".th", 50}, // Thai domain pattern
			{"_th", 45},
		},
		// System users
		systemUsers: []WeightedItem{
			{"admin", 100},
			{"user", 95},
			{"test", 90},
			{"guest", 85},
			{"root", 80},
			{"administrator", 75},
			{"webmaster", 70},
			{"support", 65},
			{"info", 60},
			{"sales", 55},
			{"contact", 50},
			{"demo", 45},
		},
		// Thai words
		thaiWords: []WeightedItem{
			{"thai", 100},
			{"thailand", 90},
			{"sawasdee", 80},
			{"kobkhun", 70},
			{"krub", 60},
			{"ka", 50},
		},
	}
}

// Generate creates a file with probability-based common Thai usernames for 2025
// If count > 0, only the first 'count' usernames will be generated
func Generate(filename string, count int) error {
	generator := NewUsernameGenerator()
	users := generator.GenerateUsernames()

	// Limit to count if specified
	if count > 0 && count < len(users) {
		users = users[:count]
	}

	content := strings.Join(users, "\n")
	return os.WriteFile(filename, []byte(content), 0644)
}

// GenerateUsernames generates usernames using probability-based strategies
func (g *UsernameGenerator) GenerateUsernames() []string {
	users := make(map[string]int) // Use map to avoid duplicates and track probability

	// Strategy 1: Pure nicknames (highest probability - most common)
	g.addPureNicknames(users)

	// Strategy 2: Nicknames + numbers (very common pattern)
	g.addNicknameWithNumbers(users)

	// Strategy 3: Nicknames + year (trending in 2025)
	g.addNicknameWithYear(users)

	// Strategy 4: Nicknames + separators + numbers (social media pattern)
	g.addNicknameWithSeparators(users)

	// Strategy 5: Thai names + numbers
	g.addNamesWithNumbers(users)

	// Strategy 6: System users + numbers/patterns
	g.addSystemUsersWithPatterns(users)

	// Strategy 7: Thai words + numbers/patterns
	g.addThaiWordsWithPatterns(users)

	// Strategy 8: Combinations (thai + user, etc.)
	g.addCombinations(users)

	// Strategy 9: Multi-nickname combinations
	g.addMultiNicknameCombinations(users)

	// Convert to sorted slice by probability (descending)
	return g.sortByProbability(users)
}

// addPureNicknames adds pure nicknames (no numbers) - highest probability
func (g *UsernameGenerator) addPureNicknames(users map[string]int) {
	for _, item := range g.nicknames {
		if item.Weight >= 60 { // Only most common
			users[item.Value] = item.Weight
		}
	}
}

// addNicknameWithNumbers adds nickname + number combinations
func (g *UsernameGenerator) addNicknameWithNumbers(users map[string]int) {
	for _, nick := range g.nicknames {
		if nick.Weight < 50 {
			continue
		}

		// Add lucky numbers (high probability)
		for _, num := range g.luckyNumbers {
			if num.Weight >= 70 {
				users[nick.Value+num.Value] = (nick.Weight + num.Weight) / 2
			}
		}

		// Add common sequences (high probability)
		for _, seq := range g.numberSequences {
			if seq.Weight >= 70 {
				users[nick.Value+seq.Value] = (nick.Weight + seq.Weight) / 2
			}
		}
	}
}

// addNicknameWithYear adds nickname + year combinations (2025 trend)
func (g *UsernameGenerator) addNicknameWithYear(users map[string]int) {
	years := []string{"2025", "2024", "2023"}
	for _, nick := range g.nicknames {
		if nick.Weight >= 60 {
			for _, year := range years {
				users[nick.Value+year] = nick.Weight - 10 // Slightly lower than pure
			}
		}
	}
}

// addNicknameWithSeparators adds nickname with separators (social media pattern)
func (g *UsernameGenerator) addNicknameWithSeparators(users map[string]int) {
	for _, nick := range g.nicknames {
		if nick.Weight >= 70 {
			for _, sep := range g.separators {
				if sep.Value == "" {
					continue
				}
				// Add separator + number
				for _, num := range g.luckyNumbers {
					if num.Weight >= 80 {
						users[nick.Value+sep.Value+num.Value] = (nick.Weight + sep.Weight + num.Weight) / 3
					}
				}
				// Add separator only (for .th pattern)
				if strings.Contains(sep.Value, "th") {
					users[nick.Value+sep.Value] = (nick.Weight + sep.Weight) / 2
				}
			}
		}
	}
}

// addNamesWithNumbers adds Thai names with numbers
func (g *UsernameGenerator) addNamesWithNumbers(users map[string]int) {
	allNames := append(g.maleNames, g.femaleNames...)

	for _, name := range allNames {
		if name.Weight >= 60 {
			// Pure name
			users[name.Value] = name.Weight

			// Name + common numbers
			for _, num := range g.luckyNumbers {
				if num.Weight >= 80 {
					users[name.Value+num.Value] = (name.Weight + num.Weight) / 2
				}
			}

			// Name + common sequences
			for _, seq := range g.numberSequences {
				if seq.Weight >= 80 {
					users[name.Value+seq.Value] = (name.Weight + seq.Weight) / 2
				}
			}
		}
	}
}

// addSystemUsersWithPatterns adds system users with various patterns
func (g *UsernameGenerator) addSystemUsersWithPatterns(users map[string]int) {
	for _, sys := range g.systemUsers {
		if sys.Weight >= 70 {
			// Pure system user
			users[sys.Value] = sys.Weight

			// System + numbers
			for _, num := range g.luckyNumbers {
				if num.Weight >= 70 {
					users[sys.Value+num.Value] = (sys.Weight + num.Weight) / 2
				}
			}

			// System + sequences
			for _, seq := range g.numberSequences {
				if seq.Weight >= 70 {
					users[sys.Value+seq.Value] = (sys.Weight + seq.Weight) / 2
				}
			}
		}
	}
}

// addThaiWordsWithPatterns adds Thai words with patterns
func (g *UsernameGenerator) addThaiWordsWithPatterns(users map[string]int) {
	for _, word := range g.thaiWords {
		if word.Weight >= 70 {
			// Pure word
			users[word.Value] = word.Weight

			// Word + numbers
			for _, num := range g.luckyNumbers {
				if num.Weight >= 70 {
					users[word.Value+num.Value] = (word.Weight + num.Weight) / 2
				}
			}

			// Word + sequences
			for _, seq := range g.numberSequences {
				if seq.Weight >= 70 {
					users[word.Value+seq.Value] = (word.Weight + seq.Weight) / 2
				}
			}
		}
	}
}

// addCombinations adds common combinations
func (g *UsernameGenerator) addCombinations(users map[string]int) {
	combinations := []struct {
		prefix string
		suffix string
		weight int
	}{
		{"thai", "user", 80},
		{"thai", "admin", 75},
		{"thai", "test", 70},
		{"user", "thai", 80},
		{"admin", "thai", 75},
		{"test", "thai", 70},
	}

	for _, combo := range combinations {
		users[combo.prefix+combo.suffix] = combo.weight
		// Add with numbers
		for _, num := range g.numberSequences {
			if num.Weight >= 80 {
				users[combo.prefix+combo.suffix+num.Value] = (combo.weight + num.Weight) / 2
			}
		}
	}
}

// addMultiNicknameCombinations adds combinations of multiple nicknames
func (g *UsernameGenerator) addMultiNicknameCombinations(users map[string]int) {
	// Most common nickname combinations
	topNicknames := []string{"nong", "aom", "ploy", "fah", "nam", "mint", "pim"}

	for i := 0; i < len(topNicknames); i++ {
		for j := i + 1; j < len(topNicknames); j++ {
			combo := topNicknames[i] + topNicknames[j]
			users[combo] = 60
			// Add with numbers
			for _, num := range g.luckyNumbers {
				if num.Weight >= 80 {
					users[combo+num.Value] = 50
				}
			}
		}
	}
}

// sortByProbability converts map to sorted slice by probability (descending)
func (g *UsernameGenerator) sortByProbability(users map[string]int) []string {
	type userProb struct {
		username string
		prob     int
	}

	var userList []userProb
	for username, prob := range users {
		userList = append(userList, userProb{username, prob})
	}

	// Sort by probability descending
	sort.Slice(userList, func(i, j int) bool {
		return userList[i].prob > userList[j].prob
	})

	result := make([]string, len(userList))
	for i, item := range userList {
		result[i] = item.username
	}

	return result
}
