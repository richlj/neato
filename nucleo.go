// The Nucelo API is used to interact with the robots themselves via some kind
// of authenticating proxy. It covers a whole range of robot commands and
// actions, all the way down to establishing a direct network connection to the
// device and issuing remote control commands.

package neato

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

const (
	nucleoAcceptHeader = "application/vnd.neato.nucleo.v1"
	nucleoHost         = "nucleo.neatocloud.com:4443"

	timeFormat = "Mon, 02 Jan 2006 15:04:05 MST"
	idLength   = 16
)

type reqID []byte

type request struct {
	ReqID  reqID   `json:"reqId"`
	Cmd    string  `json:"cmd"`
	Params *Params `json:"params,omitempty"`
}

// Params are values supplied to modify Nucleo requests. In some cases there
// are particular mandatory values. This varies between robots and software
// versions.
type Params struct {
	Category                     int      `json:"category"`
	Mode                         int      `json:"mode"`
	Modifier                     int      `json:"modifier"`
	RobotSounds                  bool     `json:"robotSounds"`
	DirtbinAlert                 bool     `json:"dirtbinAlert"`
	AllAlerts                    bool     `json:"allAlerts"`
	Leds                         bool     `json:"leds"`
	ButtonClicks                 bool     `json:"buttonClicks"`
	DirtbinAlertReminderInterval int      `json:"dirtbinAlertReminderInterval"`
	FilterChangeReminderInterval int      `json:"filterChangeReminderInterval"`
	BrushChangeReminderInterval  int      `json:"brushChangeReminderInterval"`
	Clock24H                     bool     `json:"clock24h"`
	Locale                       string   `json:"locale"`
	AvailableLocales             []string `json:"availableLocales"`
	NavigationMode               int      `json:"navigationMode"`
	BoundaryID                   string   `json:"boundaryId"`
	SpotWidth                    int      `json:"spotWidth"`
	SpotHeight                   int      `json:"spotHeight"`
	Events                       []event  `json:"events"`
}

type event struct {
	Mode       int    `json:"mode"`
	Day        int    `json:"day"`
	StartTime  string `json:"startTime"`
	BoundaryID string `json:"boundaryId"`
}

// Response combines the Standard Response and the State Response values
type Response struct {
	Version           int               `json:"version"`
	ReqID             reqID             `json:"reqId"`
	Result            string            `json:"result"`
	Data              data              `json:"data"`
	State             int               `json:"state,omitempty"`
	Action            int               `json:"action,omitempty"`
	Error             interface{}       `json:"error,omitempty"`
	Alert             string            `json:"alert,omitempty"`
	Cleaning          cleaning          `json:"cleaning,omitempty"`
	Details           details           `json:"details,omitempty"`
	AvailableCommands availableCommands `json:"availableCommands,omitempty"`
	AvailableServices availableServices `json:"availableServices,omitempty"`
	Meta              meta              `json:"meta,omitempty"`
}

type details struct {
	IsCharging        bool `json:"isCharging"`
	IsDocked          bool `json:"isDocked"`
	DockHasBeenSeen   bool `json:"dockHasBeenSeen"`
	Charge            int  `json:"charge"`
	IsScheduleEnabled bool `json:"isScheduleEnabled"`
}

type availableCommands struct {
	Start    bool `json:"start"`
	Stop     bool `json:"stop"`
	Pause    bool `json:"pause"`
	Resume   bool `json:"resume"`
	GoToBase bool `json:"goToBase"`
}

type availableServices struct {
	HouseCleaning  string `json:"houseCleaning"`
	SpotCleaning   string `json:"spotCleaning"`
	ManualCleaning string `json:"manualCleaning"`
	Schedule       string `json:"schedule"`
}

type meta struct {
	ModelName string `json:"modelName"`
	Firmware  string `json:"firmware"`
}

type battery struct {
	Level               int    `json:"level"`
	TimeToEmpty         int    `json:"timeToEmpty"`
	TimeToFullCharge    int    `json:"timeToFullCharge"`
	TotalCharges        int    `json:"totalCharges"`
	ManufacturingDate   string `json:"manufacturingDate"`
	AuthorizationStatus int    `json:"authorizationStatus"`
	Vendor              string `json:"vendor"`
}

func (r *Robot) signingString(req *request, ts string) string {
	a, _ := json.Marshal(req)
	return fmt.Sprintf("%s\n%s\n%s", strings.ToLower(r.Serial), ts, a)
}

// authorization adds a signed Authorization header to the supplied
// *http.Request
func (r *request) authorization(o *Robot, req *http.Request, ts string) error {
	req.Header.Set("Authorization", fmt.Sprintf("NEATOAPP %x", o.sign(r,
		ts)))
	return nil
}

func (r *Robot) sign(req *request, ts string) []byte {
	h := hmac.New(sha256.New, []byte(r.SecretKey))
	h.Write([]byte(r.signingString(req, ts)))
	return h.Sum(nil)
}

func (r *request) addHeaders(req *http.Request, o *Robot) error {
	ts := time.Now().Format(timeFormat)
	req.Header.Set("Accept", nucleoAcceptHeader)
	req.Header.Set("Date", ts)
	return r.authorization(o, req, ts)
}

func (r *Robot) exec(a *request) (*Response, error) {
	b, err := json.Marshal(a)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, (&url.URL{
		Scheme: scheme,
		Host:   nucleoHost,
		Path:   path.Join("vendors/neato/robots", r.Serial, "messages"),
	}).String(), bytes.NewBuffer(b))
	if err != nil {
		return nil, err
	}
	if err := a.addHeaders(req, r); err != nil {
		return nil, err
	}
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result Response
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result.checkID(a)
}

type data struct {
	Enabled                              bool      `json:"enabled,omitempty"`
	Events                               []event   `json:"events,omitempty"`
	RobotSounds                          bool      `json:"robotSounds,omitempty"`
	DirtbinAlertReminderInterval         int       `json:"dirtbinAlertReminderInterval,omitempty"`
	FilterChangeReminderInterval         int       `json:"filterChangeReminderInterval,omitempty"`
	BrushChangeReminderInterval          int       `json:"brushChangeReminderInterval,omitempty"`
	ProductNumber                        string    `json:"productNumber,omitempty"`
	Serial                               string    `json:"serial,omitempty"`
	Model                                string    `json:"model,omitempty"`
	Firmware                             string    `json:"firmware,omitempty"`
	Battery                              battery   `json:"battery,omitempty"`
	ModelName                            string    `json:"modelName,omitempty"`
	CPUMACID                             string    `json:"CPUMACID,omitempty"`
	MainBrdMfgDate                       string    `json:"MainBrdMfgDate,omitempty"`
	RobotMfgDate                         string    `json:"RobotMfgDate,omitempty"`
	BoardRev                             int       `json:"BoardRev,omitempty"`
	ChassisRev                           int       `json:"ChassisRev,omitempty"`
	BatteryType                          int       `json:"BatteryType,omitempty"`
	WheelPodType                         int       `json:"WheelPodType,omitempty"`
	DropSensorType                       int       `json:"DropSensorType,omitempty"`
	MagSensorType                        int       `json:"MagSensorType,omitempty"`
	WallSensorType                       int       `json:"WallSensorType,omitempty"`
	LDSMotorType                         int       `json:"LDSMotorType,omitempty"`
	Locale                               int       `json:"Locale,omitempty"`
	USMode                               int       `json:"USMode,omitempty"`
	NeatoServer                          string    `json:"NeatoServer,omitempty"`
	CartID                               int       `json:"CartID,omitempty"`
	BrushSpeed                           int       `json:"brushSpeed,omitempty"`
	BrushSpeedEco                        int       `json:"brushSpeedEco,omitempty"`
	VacuumSpeed                          int       `json:"vacuumSpeed,omitempty"`
	VacuumPwrPercent                     int       `json:"vacuumPwrPercent,omitempty"`
	VacuumPwrPercentEco                  int       `json:"vacuumPwrPercentEco,omitempty"`
	RunTime                              int       `json:"runTime,omitempty"`
	BrushPresent                         int       `json:"BrushPresent,omitempty"`
	VacuumPresent                        int       `json:"VacuumPresent,omitempty"`
	PadPresent                           int       `json:"PadPresent,omitempty"`
	PlatenPresent                        int       `json:"PlatenPresent,omitempty"`
	BrushDirection                       int       `json:"BrushDirection,omitempty"`
	VacuumDirection                      int       `json:"VacuumDirection,omitempty"`
	PadDirection                         int       `json:"PadDirection,omitempty"`
	CumulativeCartridgeTimeInSecs        int       `json:"CumulativeCartridgeTimeInSecs,omitempty"`
	NCleaningsStartedWhereDustBinWasFull int       `json:"nCleaningsStartedWhereDustBinWasFull,omitempty"`
	BlowerType                           int       `json:"BlowerType,omitempty"`
	BrushMotorType                       int       `json:"BrushMotorType,omitempty"`
	SideBrushType                        int       `json:"SideBrushType,omitempty"`
	SideBrushPower                       int       `json:"SideBrushPower,omitempty"`
	NAutoCycleCleaningsStarted           int       `json:"nAutoCycleCleaningsStarted,omitempty"`
	HardwareVersionMajor                 int       `json:"hardware_version_major,omitempty"`
	HardwareVersionMinor                 int       `json:"hardware_version_minor,omitempty"`
	SoftwareVersionMajor                 int       `json:"software_version_major,omitempty"`
	SoftwareVersionMinor                 int       `json:"software_version_minor,omitempty"`
	MaxVoltage                           int       `json:"max_voltage,omitempty"`
	MaxCurrent                           int       `json:"max_current,omitempty"`
	VoltageMultiplier                    int       `json:"voltage_multiplier,omitempty"`
	CurrentMultiplier                    int       `json:"current_multiplier,omitempty"`
	CapacityMode                         int       `json:"capacity_mode,omitempty"`
	DesignCapacity                       int       `json:"design_capacity,omitempty"`
	DesignVoltage                        int       `json:"design_voltage,omitempty"`
	MfgDay                               int       `json:"mfg_day,omitempty"`
	MfgMonth                             int       `json:"mfg_month,omitempty"`
	MfgYear                              int       `json:"mfg_year,omitempty"`
	SerialNumber                         int       `json:"serial_number,omitempty"`
	SwVer                                int       `json:"sw_ver,omitempty"`
	DataVer                              int       `json:"data_ver,omitempty"`
	MfgAccess                            int       `json:"mfg_access,omitempty"`
	MfgName                              string    `json:"mfg_name,omitempty"`
	DeviceName                           string    `json:"device_name,omitempty"`
	ChemistryName                        string    `json:"chemistry_name,omitempty"`
	Major                                int       `json:"Major,omitempty"`
	Minor                                int       `json:"Minor,omitempty"`
	Build                                int       `json:"Build,omitempty"`
	LdsVer                               string    `json:"ldsVer,omitempty"`
	LdsSerial                            string    `json:"ldsSerial,omitempty"`
	LdsCPU                               string    `json:"ldsCPU,omitempty"`
	LdsBuildNum                          string    `json:"ldsBuildNum,omitempty"`
	BootLoaderVersion                    int       `json:"bootLoaderVersion,omitempty"`
	UIBoardSWVer                         int       `json:"uiBoardSWVer,omitempty"`
	UIBoardHWVer                         int       `json:"uiBoardHWVer,omitempty"`
	QAState                              int       `json:"qaState,omitempty"`
	Manufacturer                         int       `json:"manufacturer,omitempty"`
	DriverVersion                        int       `json:"driverVersion,omitempty"`
	DriverID                             int       `json:"driverID,omitempty"`
	UltrasonicSW                         int       `json:"ultrasonicSW,omitempty"`
	UltrasonicHW                         int       `json:"ultrasonicHW,omitempty"`
	BlowerHW                             int       `json:"blowerHW,omitempty"`
	BlowerSWMajor                        int       `json:"blowerSWMajor,omitempty"`
	BlowerSWMinor                        int       `json:"blowerSWMinor,omitempty"`
	HouseCleaning                        cleaning  `json:"houseCleaning"`
	SpotCleaning                         cleaning  `json:"spotCleaning"`
	TotalCleanedArea                     float64   `json:"totalCleanedArea"`
	TotalCleaningTime                    int       `json:"totalCleaningTime"`
	AverageCleanedArea                   float64   `json:"averageCleanedArea"`
	AverageCleaningTime                  int       `json:"averageCleaningTime"`
	History                              []history `json:"history"`
}

type cleaning struct {
	TotalCleanedArea    float64   `json:"totalCleanedArea"`
	TotalCleaningTime   int       `json:"totalCleaningTime"`
	AverageCleanedArea  float64   `json:"averageCleanedArea"`
	AverageCleaningTime int       `json:"averageCleaningTime"`
	History             []history `json:"history"`
}

type history struct {
	Start                         time.Time `json:"start"`
	End                           time.Time `json:"end"`
	SuspendedCleaningChargingTime int       `json:"suspendedCleaningChargingTime"`
	ErrorTime                     int       `json:"errorTime"`
	PauseTime                     int       `json:"pauseTime"`
	Mode                          int       `json:"mode"`
	Area                          float64   `json:"area"`
	LaunchedFrom                  string    `json:"launchedFrom"`
	Completed                     bool      `json:"completed"`
}

func newRequest(cmd string, p *Params) (*request, error) {
	id, err := newID()
	if err != nil {
		return nil, err
	}
	return &request{
		ReqID:  id,
		Cmd:    cmd,
		Params: p,
	}, nil
}

// FindMe causes the Robot in question to emit an audible alert
func (r *Robot) FindMe(a *Params) (*Response, error) {
	req, err := newRequest("findMe", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// GetGeneralInfo returns a variety of information about the Robot
func (r *Robot) GetGeneralInfo(a *Params) (*Response, error) {
	req, err := newRequest("getGeneralInfo", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// StartCleaning makes the Robot begin a cleaning run with the supplied
// parameters
func (r *Robot) StartCleaning(a *Params) (*Response, error) {
	req, err := newRequest("startCleaning", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// StopCleaning causes the Robot to start cleaning
func (r *Robot) StopCleaning(a *Params) (*Response, error) {
	req, err := newRequest("stopCleaning", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// PauseCleaning causes the Robot to stop cleaning
func (r *Robot) PauseCleaning(a *Params) (*Response, error) {
	req, err := newRequest("pauseCleaning", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// ResumeCleaning causes the Robot to resume a cleaning run
func (r *Robot) ResumeCleaning(a *Params) (*Response, error) {
	req, err := newRequest("resumeCleaning", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// SendToBase sends the Robot back to the charging base
func (r *Robot) SendToBase(a *Params) (*Response, error) {
	req, err := newRequest("sendToBase", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// GetLocalStats returns local statistics about the Robot in question
func (r *Robot) GetLocalStats(a *Params) (*Response, error) {
	req, err := newRequest("getLocalStats", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// GetRobotManualCleaningInfo returns manual cleaning info for the given robot
func (r *Robot) GetRobotManualCleaningInfo(a *Params) (*Response, error) {
	req, err := newRequest("getRobotManualCleaningInfo", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// SetMapBoundaries sets boundary parameters for the given robot and Map
func (r *Robot) SetMapBoundaries(a *Params) (*Response, error) {
	req, err := newRequest("setMapBoundaries", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// GetMapBoundaries returns the boundary parameters for the given Robot and Map
func (r *Robot) GetMapBoundaries(a *Params) (*Response, error) {
	req, err := newRequest("getMapBoundaries", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// StartPersistentMapExploration sends the Robot on a new map exploration
func (r *Robot) StartPersistentMapExploration(a *Params) (*Response, error) {
	req, err := newRequest("startPersistentMapExploration", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// GetPreferences retrieves preferences for a Robot
func (r *Robot) GetPreferences(a *Params) (*Response, error) {
	req, err := newRequest("getPreferences", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// SetPreferences sets preferences for a Robot
func (r *Robot) SetPreferences(a *Params) (*Response, error) {
	req, err := newRequest("setPreferences", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// GetSchedule returns details of the schedule for the Robot
func (r *Robot) GetSchedule(a *Params) (*Response, error) {
	req, err := newRequest("getSchedule", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// SetSchedule sets the schedule on the Robot in question
func (r *Robot) SetSchedule(a *Params) (*Response, error) {
	req, err := newRequest("setSchedule", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// EnableSchedule enables the schedule on the Robot in question
func (r *Robot) EnableSchedule(a *Params) (*Response, error) {
	req, err := newRequest("enableSchedule", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// DisableSchedule disables the schedule on the Robot in question
func (r *Robot) DisableSchedule(a *Params) (*Response, error) {
	req, err := newRequest("disableSchedule", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

// GetRobotInfo returns information about that Robot
func (r *Robot) GetRobotInfo(a *Params) (*Response, error) {
	req, err := newRequest("getRobotInfo", a)
	if err != nil {
		return nil, err
	}
	return r.exec(req)
}

func (resp *Response) checkID(a *request) (*Response, error) {
	if string(resp.ReqID) != string(a.ReqID) {
		return nil, fmt.Errorf("conflicting ReqID value")
	}
	return resp, nil
}

func newID() (reqID, error) {
	raw := make([]byte, idLength)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	result := make(reqID, hex.EncodedLen(len(raw)))
	_ = hex.Encode(result, raw)
	return result, nil
}
