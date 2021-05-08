using Microsoft.Extensions.Options;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Rnwood.Smtp4dev.DbModel;
using Rnwood.Smtp4dev.Hubs;
using Rnwood.SmtpServer;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using MimeKit;
using MailKit.Net.Smtp;
using System.Reactive.Linq;
using System.Linq.Expressions;
using Serilog;

namespace Rnwood.Smtp4dev.Server
{
    public class Smtp4devServer : IMessagesRepository
    {
        private readonly ILogger log = Log.ForContext<Smtp4devServer>();

        public Smtp4devServer(Func<Smtp4devDbContext> dbContextFactory, IOptionsMonitor<ServerOptions> serverOptions,
            IOptionsMonitor<RelayOptions> relayOptions, NotificationsHub notificationsHub, Func<RelayOptions, SmtpClient> relaySmtpClientFactory)
        {
            this.notificationsHub = notificationsHub;
            this.serverOptions = serverOptions;
            this.relayOptions = relayOptions;
            this.dbContextFactory = dbContextFactory;
            this.relaySmtpClientFactory = relaySmtpClientFactory;

            DoCleanup();

            IDisposable eventHandler = null;
            var obs = Observable.FromEvent<ServerOptions>(e => eventHandler = serverOptions.OnChange(e), e => eventHandler.Dispose());
            obs.Throttle(TimeSpan.FromMilliseconds(100)).Subscribe(OnServerOptionsChanged);

            taskQueue.Start();

        }

        private void OnServerOptionsChanged(ServerOptions arg1)
        {
            if (this.smtpServer?.IsRunning == true)
            {
                log.Information("ServerOptions changed. Restarting server...");
                Stop();
                TryStart();
            }
            else
            {
                log.Information("ServerOptions changed.");
            }


        }

        private void CreateSmtpServer()
        {
            X509Certificate2 cert = GetTlsCertificate();

            ServerOptions serverOptionsValue = serverOptions.CurrentValue;
            this.smtpServer = new DefaultServer(serverOptionsValue.AllowRemoteConnections, serverOptionsValue.HostName, serverOptionsValue.Port,
                serverOptionsValue.TlsMode == TlsMode.ImplicitTls ? cert : null,
                serverOptionsValue.TlsMode == TlsMode.StartTls ? cert : null
            );
            this.smtpServer.MessageReceivedEventHandler += OnMessageReceived;
            this.smtpServer.SessionCompletedEventHandler += OnSessionCompleted;
            this.smtpServer.SessionStartedHandler += OnSessionStarted;
            this.smtpServer.AuthenticationCredentialsValidationRequiredEventHandler += OnAuthenticationCredentialsValidationRequired;
            this.smtpServer.IsRunningChanged += ((_, __) =>
            {
                if (!this.smtpServer.IsRunning)
                {
                    log.Information("SMTP server stopped");
                    this.notificationsHub.OnServerChanged().Wait();
                }
            });
        }

        internal void Stop()
        {
            log.Information("SMTP server stopping...");
            this.smtpServer.Stop(true);
        }

        private X509Certificate2 GetTlsCertificate()
        {
            System.Security.Cryptography.X509Certificates.X509Certificate2 cert = null;

            log.Information("TLS mode: {TLSMode}",serverOptions.CurrentValue.TlsMode);

            if (serverOptions.CurrentValue.TlsMode != TlsMode.None)
            {

                if (!string.IsNullOrEmpty(serverOptions.CurrentValue.TlsCertificate))
                {
                    log.Information("Using certificate from {certificateLocation}",serverOptions.CurrentValue.TlsCertificate);
                    cert = new X509Certificate2(File.ReadAllBytes(serverOptions.CurrentValue.TlsCertificate), "", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

                }
                else
                {
                    string pfxPath = Path.GetFullPath("selfsigned-certificate.pfx");
                    string cerPath = Path.GetFullPath("selfsigned-certificate.cer");

                    if (File.Exists(pfxPath))
                    {
                        cert = new X509Certificate2(File.ReadAllBytes(pfxPath), "", X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);

                        if (cert.Subject != $"CN={serverOptions.CurrentValue.HostName}" || DateTime.Parse(cert.GetExpirationDateString()) < DateTime.Now.AddDays(30))
                        {
                            cert = null;
                        }
                        else
                        {
                            log.Information("Using existing self-signed certificate with subject name '{certificateSubject}' and expiry date {certificateExpiryDate}",serverOptions.CurrentValue.HostName,
                                cert.GetExpirationDateString());
                        }
                    }

                    if (cert == null)
                    {
                        cert = SSCertGenerator.CreateSelfSignedCertificate(serverOptions.CurrentValue.HostName);
                        File.WriteAllBytes(pfxPath, cert.Export(X509ContentType.Pkcs12));
                        File.WriteAllBytes(cerPath, cert.Export(X509ContentType.Cert));
                        log.Information("Generated new self-signed certificate with subject name '{certificateHostName}' and expiry date {certificateExpiryDate}", serverOptions.CurrentValue.HostName, cert.GetExpirationDateString());
                    }

                    log.Information($"Ensure that the hostname you enter into clients and '{serverOptions.CurrentValue.HostName}' from ServerOptions:HostName configuration match exactly");
                    log.Information($"and trust the issuer certificate at {cerPath} in your client/OS to avoid certificate validation errors.");
                }
            }
            return cert;
        }

        private void DoCleanup()
        {
            Smtp4devDbContext dbContent = this.dbContextFactory();

            foreach (Session unfinishedSession in dbContent.Sessions.Where(s => !s.EndDate.HasValue).ToArray())
            {
                unfinishedSession.EndDate = DateTime.Now;
            }
            dbContent.SaveChanges();

            TrimMessages(dbContent);
            dbContent.SaveChanges();

            TrimSessions(dbContent);
            dbContent.SaveChanges();

            this.notificationsHub.OnMessagesChanged().Wait();
            this.notificationsHub.OnSessionsChanged().Wait();
        }

        private Task OnAuthenticationCredentialsValidationRequired(object sender, AuthenticationCredentialsValidationEventArgs e)
        {
            e.AuthenticationResult = AuthenticationResult.Success;
            return Task.CompletedTask;
        }


        private readonly IOptionsMonitor<ServerOptions> serverOptions;
        private readonly IOptionsMonitor<RelayOptions> relayOptions;
        private readonly IDictionary<ISession, Guid> activeSessionsToDbId = new Dictionary<ISession, Guid>();

        private static async Task UpdateDbSession(ISession session, Session dbSession)
        {
            dbSession.StartDate = session.StartDate;
            dbSession.EndDate = session.EndDate;
            dbSession.ClientAddress = session.ClientAddress.ToString();
            dbSession.ClientName = session.ClientName;
            dbSession.NumberOfMessages = (await session.GetMessages()).Count;
            dbSession.Log = (await session.GetLog()).ReadToEnd();
            dbSession.SessionErrorType = session.SessionErrorType;
            dbSession.SessionError = session.SessionError?.ToString();
        }

        public IQueryable<DbModel.Message> GetMessages()
        {
            return dbContextFactory().Messages;
        }


        public Task MarkMessageRead(Guid id)
        {
            return taskQueue.QueueTask(() =>
            {
                Smtp4devDbContext dbContent = dbContextFactory();
                DbModel.Message message = dbContent.Messages.FindAsync(id).Result;

                if (message?.IsUnread == true)
                {
                    message.IsUnread = false;
                    dbContent.SaveChanges();
                    notificationsHub.OnMessagesChanged().Wait();
                }
            }, true);
        }

        private async Task OnSessionStarted(object sender, SessionEventArgs e)
        {
            log.Information("Session started. Client address {clientAddress}.", e.Session.ClientAddress);
            await taskQueue.QueueTask(() =>
            {

                Smtp4devDbContext dbContent = dbContextFactory();

                Session dbSession = new Session();
                UpdateDbSession(e.Session, dbSession).Wait();
                dbContent.Sessions.Add(dbSession);
                dbContent.SaveChanges();

                activeSessionsToDbId[e.Session] = dbSession.Id;

            }, false).ConfigureAwait(false);
        }

        private async Task OnSessionCompleted(object sender, SessionEventArgs e)
        {
            int messageCount = (await e.Session.GetMessages()).Count;
            log.Information("Session completed. Client address {clientAddress}. Number of messages {messageCount}.", e.Session.ClientAddress, messageCount);


            await taskQueue.QueueTask(() =>
            {
                Smtp4devDbContext dbContent = dbContextFactory();

                Session dbSession = dbContent.Sessions.Find(activeSessionsToDbId[e.Session]);
                UpdateDbSession(e.Session, dbSession).Wait();
                dbContent.SaveChanges();

                TrimSessions(dbContent);
                dbContent.SaveChanges();

                activeSessionsToDbId.Remove(e.Session);

                notificationsHub.OnSessionsChanged().Wait();

            }, false).ConfigureAwait(false);
        }



        internal Task DeleteSession(Guid id)
        {
            return taskQueue.QueueTask(() =>
            {
                Smtp4devDbContext dbContext = dbContextFactory();

                Session session = dbContext.Sessions.FirstOrDefault(s => s.Id == id);
                if (session != null)
                {
                    dbContext.Sessions.Remove(session);
                    dbContext.SaveChanges();
                    notificationsHub.OnSessionsChanged().Wait();
                }
            }, true);
        }

        internal Task DeleteAllSessions()
        {
            return taskQueue.QueueTask(() =>
            {
                Smtp4devDbContext dbContext = dbContextFactory();
                dbContext.Sessions.RemoveRange(dbContext.Sessions.Where(s => s.EndDate.HasValue));
                dbContext.SaveChanges();
                notificationsHub.OnSessionsChanged().Wait();
            }, true);
        }

        private async Task OnMessageReceived(object sender, MessageEventArgs e)
        {
            Message message = new MessageConverter().ConvertAsync(e.Message).Result;
            log.Information("Message received. Client address {clientAddress}. From {messageFrom}. To {messageTo}.", e.Message.Session.ClientAddress, e.Message.From, message.To);
            message.IsUnread = true;


            await taskQueue.QueueTask(() =>
            {
                log.Information("Processing received message");
                Smtp4devDbContext dbContext = dbContextFactory();

                Dictionary<MailboxAddress, Exception> relayErrors = TryRelayMessage(message, null);
                message.RelayError = string.Join("\n", relayErrors.Select(e => e.Key.ToString() + ": " + e.Value.Message));

                ImapState imapState = dbContext.ImapState.Single();
                imapState.LastUid = Math.Max(0, imapState.LastUid + 1);
                message.ImapUid = imapState.LastUid;


                Session dbSession = dbContext.Sessions.Find(activeSessionsToDbId[e.Message.Session]);
                message.Session = dbSession;
                dbContext.Messages.Add(message);

                dbContext.SaveChanges();

                TrimMessages(dbContext);
                dbContext.SaveChanges();
                notificationsHub.OnMessagesChanged().Wait();
                log.Information("Processing received message DONE");

            }, false).ConfigureAwait(false);
        }

        public Dictionary<MailboxAddress, Exception> TryRelayMessage(Message message, MailboxAddress[] overrideRecipients)
        {
            Dictionary<MailboxAddress, Exception> result = new Dictionary<MailboxAddress, Exception>();

            if (!relayOptions.CurrentValue.IsEnabled)
            {
                return result;
            }

            MailboxAddress[] recipients;

            if (overrideRecipients == null)
            {
                recipients = message.To
                    .Split(",")
                    .Select(r => MailboxAddress.Parse(r))
                    .Where(r => relayOptions.CurrentValue.AutomaticEmails.Contains(r.Address, StringComparer.OrdinalIgnoreCase))
                    .ToArray();
            }
            else
            {
                recipients = overrideRecipients;
            }

            foreach (MailboxAddress recipient in recipients)
            {
                try
                {

                    log.Information("Relaying message to {recipient}", recipient);

                    using (SmtpClient relaySmtpClient = relaySmtpClientFactory(relayOptions.CurrentValue))
                    {
                        var apiMsg = new ApiModel.Message(message);
                        MimeMessage newEmail = apiMsg.MimeMessage;
                        MailboxAddress sender = MailboxAddress.Parse(
                            !string.IsNullOrEmpty(relayOptions.CurrentValue.SenderAddress)
                            ? relayOptions.CurrentValue.SenderAddress
                            : apiMsg.From);
                        relaySmtpClient.Send(newEmail, sender, new[] { recipient });
                    }


                }
                catch (Exception e)
                {
                    log.Error(e, "Can not relay message to {recipient}: {errorMessage}", recipient, e.ToString());
                    result[recipient] = e;
                }
            }

            return result;
        }

        public Task DeleteMessage(Guid id)
        {
            return taskQueue.QueueTask(() =>
            {
                Smtp4devDbContext dbContext = dbContextFactory();
                dbContext.Messages.RemoveRange(dbContext.Messages.Where(m => m.Id == id));
                dbContext.SaveChanges();
                notificationsHub.OnMessagesChanged().Wait();
            }, true);
        }


        public Task DeleteAllMessages()
        {
            return taskQueue.QueueTask(() =>
            {
                Smtp4devDbContext dbContext = dbContextFactory();
                dbContext.Messages.RemoveRange(dbContext.Messages);
                dbContext.SaveChanges();
                notificationsHub.OnMessagesChanged().Wait();
            }, true);
        }



        private void TrimMessages(Smtp4devDbContext dbContext)
        {
            dbContext.Messages.RemoveRange(dbContext.Messages.OrderByDescending(m => m.ReceivedDate).Skip(serverOptions.CurrentValue.NumberOfMessagesToKeep));
        }

        private void TrimSessions(Smtp4devDbContext dbContext)
        {
            dbContext.Sessions.RemoveRange(dbContext.Sessions.Where(s => s.EndDate.HasValue).OrderByDescending(m => m.EndDate).Skip(serverOptions.CurrentValue.NumberOfSessionsToKeep));
        }


        private readonly Func<Smtp4devDbContext> dbContextFactory;
        private TaskQueue taskQueue = new TaskQueue();
        private DefaultServer smtpServer;
        private Func<RelayOptions, SmtpClient> relaySmtpClientFactory;
        private NotificationsHub notificationsHub;

        public Exception Exception { get; private set; }

        public bool IsRunning
        {
            get
            {
                return this.smtpServer.IsRunning;
            }
        }

        public int PortNumber
        {
            get
            {
                return this.smtpServer.PortNumber;
            }
        }

        public void TryStart()
        {
            try
            {
                this.Exception = null;

                CreateSmtpServer();
                smtpServer.Start();

                log.Information("SMTP Server is listening on port {smtpPortNumber}.", 
                    smtpServer.PortNumber);
                log.Information("Keeping last {messagesToKeep} messages and {sessionsToKeep} sessions.", serverOptions.CurrentValue.NumberOfMessagesToKeep, serverOptions.CurrentValue.NumberOfSessionsToKeep);
            }
            catch (Exception e)
            {
                log.Fatal(e, "The SMTP server failed to start: {failureReason}",e.ToString());
                this.Exception = e;
            }
            finally
            {
                this.notificationsHub.OnServerChanged().Wait();
            }
        }
    }
}
