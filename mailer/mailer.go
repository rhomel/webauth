package mailer

import "bytes"
import "github.com/mailgun/mailgun-go"
//import "fmt"
import "text/template"
import templateHtml "html/template"
import "os"
import "log"
import "bufio"
import "io"

const ResetTokenTextTemplate = `A request to reset your password has been received. \n\nIf you did not request to reset your password, please ignore this message.\n\nGo to: {{.ResetUri}} to reset your password.`
const ResetTokenHtmlTemplate = `<h2>{{.Host}} Password Reset Request</h2><p>A request to reset your password has been received. <strong>If you did not request to reset your password, please ignore this message.</strong></p><p>Go to <a href="{{.ResetUri}}">{{.ResetUri}}</a> to reset your password.</p>`

type ResetTokenMailer struct {
    TextTemplate *template.Template
    HtmlTemplate *templateHtml.Template
    Host string
    ResetUri string
    Mg mailgun.Mailgun
    PublicKey string
    Log *log.Logger
    LogFile *bufio.Writer
}

type ResetMailer interface {
    Send(token string, email string)
}

type tokenBody struct {
    Token string
    ResetUri string
    Host string
}

type TemplateExecutor interface {
    Execute(wr io.Writer, data interface{}) error
}

func NewResetTokenMailer(host string, resetUriPath string, mgPrivateKey string, mgPublicKey string, TextFile string, HtmlFile string) (*ResetTokenMailer, error) {
    mailer := ResetTokenMailer{}

    mailer.Host = host
    mailer.ResetUri = "http://" + host + resetUriPath

    mailer.Mg = mailgun.NewMailgun(host, mgPrivateKey, mgPublicKey)

    logfile, err := os.Create("mail.log")
    if err != nil {
        return nil, err
    }
    mailer.LogFile = bufio.NewWriter(logfile)
    mailer.Log = log.New(mailer.LogFile, "", log.LstdFlags)

    if TextFile == "" {
        // standard built-in template
        mailer.TextTemplate, err = template.New("resetTokenEmail").Parse(ResetTokenTextTemplate)
    } else {
        // read from file
        mailer.TextTemplate, err = template.New("resetTokenEmail").ParseFiles(TextFile)
    }

    if err != nil || mailer.TextTemplate == nil {
        return nil, err
    }

    if HtmlFile == "" {
        // standard built-in template
        mailer.HtmlTemplate, err = templateHtml.New("resetTokenEmail").Parse(ResetTokenHtmlTemplate)
    } else {
        // read from file
        mailer.HtmlTemplate, err = templateHtml.New("resetTokenEmail").ParseFiles(HtmlFile)
    }

    if err != nil || mailer.HtmlTemplate == nil {
        return nil, err
    }

    return &mailer, nil
}

func (m *ResetTokenMailer) templatize(templater TemplateExecutor, params interface{}) string {
    var buffer bytes.Buffer
    templater.Execute(&buffer, params)
    return buffer.String()
}

func (m *ResetTokenMailer) getHtml(token string) string {
    params := tokenBody{token,m.ResetUri,m.Host}
    return m.templatize(m.HtmlTemplate, params)
}

func (m *ResetTokenMailer) getText(token string) string {
    params := tokenBody{token,m.ResetUri,m.Host}
    return m.templatize(m.TextTemplate, params)
}

func (m *ResetTokenMailer) Send(token string, email string) {
    host := m.Host
    sender := host + " Support <support@" + host + ">"
    title := host + " Reset Password Request"

    plain := m.getText(token)
    html := m.getHtml(token)

    m.Log.Printf("Plain Body:\n%v\n", plain)
    m.Log.Printf("Html Body:\n%v\n", html)
    //return

    message := m.Mg.NewMessage(sender, title, plain, email)
    message.SetHtml(html)

    response, id, _ := m.Mg.Send(message)

    m.Log.Printf("Response ID: %s\n", id)
    m.Log.Printf("Message from server: %s\n", response)

}

