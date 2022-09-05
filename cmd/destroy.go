package cmd

import (
	"fmt"
	"log"

	"github.com/packethost/packngo"
	"github.com/spf13/cobra"
)

var destroyCmd = &cobra.Command{
	Use:   "destroy <tag>",
	Short: "destroy a Kubernetes cluster, by providing its unique tag",
	Long: `Destroy a previously created Kubernetes cluster on Equinix Metal, by providing its unique tag. Removes
	all used Equinix Metal resources.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		// get EQXM client
		log.Print("creating Equinix Metal client...")
		client := packngo.NewClientWithAuth("equinix-metal-k8s", token, nil)
		client.UserAgent = fmt.Sprintf("equinix-metal-k8s/%s %s", version, client.UserAgent)
		log.Println("done")

		tag := args[0]

		// find all devices with given tag
		devs, _, err := client.Devices.List(project, &packngo.ListOptions{
			QueryParams: map[string]string{"tag": tag},
		})
		if err != nil {
			log.Fatal(err)
		}
		// delete all of the devices
		log.Println("deleting devices")
		for _, dev := range devs {
			log.Printf("\t%s ", dev.ID)
			if _, err := client.Devices.Delete(dev.ID, true); err != nil {
				log.Fatal(err)
			}
			log.Println("done")
		}
		log.Println("all devices deleted")

		// delete EIP
		log.Println("deleting EIPs")
		reservations, _, err := client.ProjectIPs.List(project, &packngo.GetOptions{
			QueryParams: map[string]string{"tag": tag},
		})
		if err != nil {
			log.Fatal(err)
		}
		for _, ip := range reservations {
			log.Printf("\t%s ", ip.ID)
			if _, err := client.ProjectIPs.Delete(ip.ID); err != nil {
				log.Fatal(err)
			}
			log.Println("done")
		}
		log.Println("all EIPs deleted")
		log.Println("delete complete")
	},
}

func destroyInit() {
}
