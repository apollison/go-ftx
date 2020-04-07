package rest_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/go-numb/go-ftx/auth"

	"github.com/stretchr/testify/assert"

	"github.com/go-numb/go-ftx/rest"
	"github.com/go-numb/go-ftx/rest/private/account"
	"github.com/go-numb/go-ftx/rest/private/fills"
	"github.com/go-numb/go-ftx/rest/private/funding"
	"github.com/go-numb/go-ftx/rest/private/orders"
	"github.com/go-numb/go-ftx/rest/private/wallet"
	"github.com/go-numb/go-ftx/types"
)

func TestInformation(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.Information(&account.RequestForInformation{})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestPositions(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.Positions(&account.RequestForPositions{})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestLeverage(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.Leverage(&account.RequestForLeverage{
		Leverage: 3,
	})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestCoins(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.Coins(&wallet.RequestForCoins{})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestBalances(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.Balances(&wallet.RequestForBalances{})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestBalancesAll(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.BalancesAll(&wallet.RequestForBalancesAll{})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestDepositAddress(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.DepositAddress(&wallet.RequestForDepositAddress{
		"BTC",
	})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestDepositHistories(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.DepositHistories(&wallet.RequestForDepositHistories{})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestWithdrawHistories(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.WithdrawHistories(&wallet.RequestForWithdrawHistories{})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestWithdraw(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.Withdraw(&wallet.RequestForWithdraw{})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestOpenOrder(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.OpenOrder(&orders.RequestForOpenOrder{})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestOrderHistories(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.OrderHistories(&orders.RequestForHistories{})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestOpenTriggerOrders(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.OpenTriggerOrders(&orders.RequestForOpenTriggerOrders{})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestOrderTriggers(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.OrderTriggers(&orders.RequestForOrderTriggers{
		CID: "38066650",
	})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestOrderTriggerHistories(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.OrderTriggerHistories(&orders.RequestForOrderTriggerHistories{})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

// TODO: in production
func TestPlaceOrder(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.PlaceOrder(&orders.RequestForPlaceOrder{
		Type:   types.LIMIT,
		Market: "BTC-PERP",
		Side:   types.BUY,
		Price:  6200,
		Size:   0.01,
		// Optionals
		ClientID:   "use_original_client_id",
		Ioc:        false,
		ReduceOnly: false,
		PostOnly:   false,
	})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

// TODO: in production
func TestPlaceTriggerOrder(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.PlaceTriggerOrder(&orders.RequestForPlaceTriggerOrder{
		Type:         "trailingStop",
		Market:       "BTC-PERP",
		Side:         types.BUY,
		TriggerPrice: 6200,
		Size:         0.01,
		// Optionals
		ReduceOnly:       false,
		RetryUntilFilled: false,
	})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

// TODO: in production
func TestModifyOrder(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.ModifyOrder(&orders.RequestForModifyOrder{
		OrderID: "erafa",
		// prioritize ClientID > OrderID
		ClientID: "use_original_client_id",
		Price:    6200,
		Size:     0.01,
	})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestModifyTriggerOrder(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	// https://docs.ftx.com/#modify-trigger-order
	res, err := c.ModifyTriggerOrder(&orders.RequestForModifyTriggerOrder{
		OrderID:      "erafa",
		TriggerPrice: 6200,
		OrderPrice:   6210,
		Size:         0.01,
	})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestOrderStatus(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.OrderStatus(&orders.RequestForOrderStatus{
		OrderID: "erafa",
		// prioritize clientID
		ClientID: "",
	})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestCancelByID(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.CancelByID(&orders.RequestForCancelByID{
		OrderID: "erafa",
		// prioritize clientID
		ClientID: "",
	})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestCancelAll(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.CancelAll(&orders.RequestForCancelAll{
		ProductCode: "",
		// optionals
		ConditionalOrdersOnly: false,
		LimitOrdersOnly:       false,
	})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}
func TestFills(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.Fills(&fills.Request{
		ProductCode: "",
	})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}

func TestFunding(t *testing.T) {
	c := rest.New(auth.New(os.Getenv("FTXKEY"), os.Getenv("FTXSECRET")))

	res, err := c.Funding(&funding.Request{
		ProductCode: "BTC-PERP",
	})
	assert.NoError(t, err)

	fmt.Printf("%+v\n", res)
}
